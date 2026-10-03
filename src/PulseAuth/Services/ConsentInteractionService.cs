using System.Security.Claims;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Constants;
using PulseAuth.Models;
using PulseAuth.Validators;

namespace PulseAuth.Services;

/// <summary>An authorization request waiting for the user's consent.</summary>
/// <param name="Client">The client asking for access (show <c>ClientName</c>, <c>LogoUri</c>, <c>Description</c>).</param>
/// <param name="RequestedScopes">Scopes requested by the client.</param>
/// <param name="ReturnUrl">The validated authorize URL to continue the flow.</param>
public sealed record ConsentRequest(Client Client, IReadOnlyList<string> RequestedScopes, string ReturnUrl);

/// <summary>
/// API for the consent page of the host application (<see cref="PulseAuthOptions.ConsentPath"/>).
/// </summary>
/// <example>
/// <code>
/// // GET /Consent?returnUrl=...
/// var request = await consent.GetConsentRequestAsync(returnUrl);   // null => invalid request
/// // POST (with antiforgery): user clicked "Allow"
/// return Redirect(await consent.GrantConsentAsync(returnUrl, User, selectedScopes, remember));
/// // POST: user clicked "Deny"
/// return Redirect(await consent.DenyConsentAsync(returnUrl) ?? "/");
/// </code>
/// </example>
public interface IConsentInteractionService
{
    /// <summary>
    /// Parses and validates the <c>returnUrl</c> the consent page received. Returns null if it is
    /// not a valid authorization request of this server (never redirect to it in that case).
    /// </summary>
    Task<ConsentRequest?> GetConsentRequestAsync(string returnUrl, CancellationToken ct = default);

    /// <summary>
    /// Stores the user's consent and returns the URL to redirect the browser to (continues the
    /// authorization). <paramref name="grantedScopes"/> may be a subset of the requested scopes
    /// (null = all); <c>openid</c> is always kept when requested.
    /// </summary>
    /// <param name="returnUrl">The returnUrl received by the consent page.</param>
    /// <param name="user">The signed-in user.</param>
    /// <param name="grantedScopes">Scopes the user accepted (null = all requested).</param>
    /// <param name="remember">False = "allow this time only".</param>
    /// <param name="ct">Cancellation token.</param>
    Task<string> GrantConsentAsync(string returnUrl, ClaimsPrincipal user,
        IEnumerable<string>? grantedScopes = null, bool remember = true, CancellationToken ct = default);

    /// <summary>
    /// Returns the client redirect URL carrying <c>error=access_denied</c>, or null if the request
    /// is invalid.
    /// </summary>
    Task<string?> DenyConsentAsync(string returnUrl, CancellationToken ct = default);

    /// <summary>The consents of a user (e.g. for a "connected apps" page).</summary>
    Task<IReadOnlyList<Consent>> GetUserConsentsAsync(string subjectId, CancellationToken ct = default);

    /// <summary>
    /// Withdraws a user's consent for a client and revokes the refresh tokens and reference
    /// tokens the client holds for that user.
    /// </summary>
    Task RevokeConsentAsync(string subjectId, string clientId, CancellationToken ct = default);
}

/// <summary>Default <see cref="IConsentInteractionService"/>.</summary>
public class ConsentInteractionService : IConsentInteractionService
{
    private static readonly TimeSpan OneTimeConsentLifetime = TimeSpan.FromMinutes(10);

    private readonly AuthorizeRequestValidator _validator;
    private readonly IConsentStore             _consents;
    private readonly IRefreshTokenStore        _refreshTokens;
    private readonly IReferenceTokenStore      _referenceTokens;
    private readonly PulseAuthOptions          _options;

    /// <summary>Initializes a new instance of the <see cref="ConsentInteractionService"/> class.</summary>
    public ConsentInteractionService(
        AuthorizeRequestValidator validator,
        IConsentStore consents,
        IRefreshTokenStore refreshTokens,
        IReferenceTokenStore referenceTokens,
        IOptions<PulseAuthOptions> options)
    {
        _validator       = validator;
        _consents        = consents;
        _refreshTokens   = refreshTokens;
        _referenceTokens = referenceTokens;
        _options         = options.Value;
    }

    /// <inheritdoc />
    public async Task<ConsentRequest?> GetConsentRequestAsync(string returnUrl, CancellationToken ct = default)
    {
        var parsed = await ParseAsync(returnUrl, ct);
        return parsed is { Validation.IsValid: true }
            ? new ConsentRequest(parsed.Value.Validation.Client!, parsed.Value.Validation.RequestedScopes, returnUrl)
            : null;
    }

    /// <inheritdoc />
    public async Task<string> GrantConsentAsync(
        string returnUrl, ClaimsPrincipal user, IEnumerable<string>? grantedScopes = null,
        bool remember = true, CancellationToken ct = default)
    {
        var parsed = await ParseAsync(returnUrl, ct);
        if (parsed is not { Validation.IsValid: true } p)
            throw new InvalidOperationException("The returnUrl is not a valid authorization request.");

        var subjectId = user.FindFirst("sub")?.Value ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? throw new InvalidOperationException("The user has no 'sub' / NameIdentifier claim.");

        var requested = p.Validation.RequestedScopes;
        var granted   = grantedScopes is null
            ? requested.ToList()
            : requested.Where(s => grantedScopes.Contains(s, StringComparer.Ordinal)).ToList();

        // openid is what makes this an OIDC sign-in: never drop it when it was requested.
        if (requested.Contains(StandardScopes.OpenId) && !granted.Contains(StandardScopes.OpenId))
            granted.Insert(0, StandardScopes.OpenId);

        var now = DateTime.UtcNow;
        var scopesToStore = granted.AsEnumerable();
        if (remember)
        {
            // Keep scopes the user granted earlier (a later request may ask for fewer scopes).
            var existing = await _consents.GetAsync(subjectId, p.Validation.Client!.ClientId, ct);
            if (existing is { Remember: true } && existing.IsValid(now))
                scopesToStore = existing.Scopes.Union(granted, StringComparer.Ordinal);
        }

        await _consents.StoreAsync(new Consent
        {
            SubjectId = subjectId,
            ClientId  = p.Validation.Client!.ClientId,
            Scopes    = scopesToStore.ToList(),
            CreatedAt = now,
            Remember  = remember,
            ExpiresAt = remember
                ? (_options.RememberedConsentLifetime is { } lifetime ? now + lifetime : null)
                : now + OneTimeConsentLifetime,
        }, ct);

        // Continue the flow asking only for the granted scopes.
        return ReplaceQueryValue(returnUrl, "scope", string.Join(' ', granted));
    }

    /// <inheritdoc />
    public async Task<string?> DenyConsentAsync(string returnUrl, CancellationToken ct = default)
    {
        var parsed = await ParseAsync(returnUrl, ct);
        if (parsed is not { } p || p.Validation.ValidatedRedirectUri is null)
            return null;

        var parameters = new Dictionary<string, string?>
        {
            ["error"]             = "access_denied",
            ["error_description"] = "The user denied the request",
        };
        if (p.Query.TryGetValue("state", out var state) && !string.IsNullOrEmpty(state))
            parameters["state"] = state.ToString();

        return QueryHelpers.AddQueryString(p.Validation.ValidatedRedirectUri, parameters);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<Consent>> GetUserConsentsAsync(string subjectId, CancellationToken ct = default)
        => _consents.GetBySubjectAsync(subjectId, ct);

    /// <inheritdoc />
    public async Task RevokeConsentAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        await _consents.RemoveAsync(subjectId, clientId, ct);
        await _refreshTokens.RevokeBySubjectAsync(subjectId, clientId, ct);
        await _referenceTokens.RemoveBySubjectAsync(subjectId, clientId, ct);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private async Task<(AuthorizeValidationResult Validation, Dictionary<string, Microsoft.Extensions.Primitives.StringValues> Query)?>
        ParseAsync(string returnUrl, CancellationToken ct)
    {
        // Only a LOCAL authorize URL of this server is accepted (no open redirect).
        if (string.IsNullOrEmpty(returnUrl) || returnUrl[0] != '/' ||
            returnUrl.StartsWith("//", StringComparison.Ordinal) || returnUrl.StartsWith("/\\", StringComparison.Ordinal))
            return null;

        var queryStart = returnUrl.IndexOf('?');
        var path       = queryStart < 0 ? returnUrl : returnUrl[..queryStart];
        if (!path.EndsWith(_options.RoutePrefix.TrimEnd('/') + "/authorize", StringComparison.OrdinalIgnoreCase))
            return null;

        var query = QueryHelpers.ParseQuery(queryStart < 0 ? string.Empty : returnUrl[queryStart..]);
        string Get(string name) => query.TryGetValue(name, out var v) ? v.ToString() : string.Empty;

        var validation = await _validator.ValidateAsync(
            Get("client_id"), Get("response_type"), Get("redirect_uri"), Get("scope"),
            Get("code_challenge"), Get("code_challenge_method"), ct);

        return (validation, query);
    }

    private static string ReplaceQueryValue(string url, string name, string value)
    {
        var queryStart = url.IndexOf('?');
        var path       = queryStart < 0 ? url : url[..queryStart];
        var query      = QueryHelpers.ParseQuery(queryStart < 0 ? string.Empty : url[queryStart..]);

        var parameters = new List<KeyValuePair<string, string?>>();
        foreach (var (key, values) in query)
        {
            if (key == name) continue;
            foreach (var v in values)
                parameters.Add(new(key, v));
        }
        parameters.Add(new(name, value));
        return QueryHelpers.AddQueryString(path, parameters);
    }
}
