using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Models;
using PulseAuth.Validators;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles GET/POST /connect/authorize
/// Implements the OAuth2 Authorization Code flow with PKCE.
/// </summary>
internal static class AuthorizeEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext                  ctx,
        IOptions<PulseAuthOptions>   optionsAccessor,
        AuthorizeRequestValidator    validator,
        IAuthorizationCodeStore      codeStore,
        IConsentStore                consentStore,
        CancellationToken            ct)
    {
        var options = optionsAccessor.Value;

        // OIDC Core §3.1.2.1: the authorization endpoint MUST support GET and POST. Form parameters
        // are copied into the query so the rest of the flow (and the login returnUrl) is identical.
        if (HttpMethods.IsPost(ctx.Request.Method))
        {
            if (!ctx.Request.HasFormContentType)
                return Results.BadRequest(new { error = Constants.OAuthErrors.InvalidRequest, error_description = "POST requests must use application/x-www-form-urlencoded" });

            var form = await ctx.Request.ReadFormAsync(ct);
            ctx.Request.Query = new QueryCollection(form.ToDictionary(kv => kv.Key, kv => kv.Value));
        }

        var q       = ctx.Request.Query;

        var clientId           = q["client_id"].ToString();
        var responseType       = q["response_type"].ToString();
        var redirectUri        = q["redirect_uri"].ToString();
        var scope              = q["scope"].ToString();
        var state              = q["state"].ToString();
        var codeChallenge      = q["code_challenge"].ToString();
        var codeChallengeMethod = q["code_challenge_method"].ToString();
        var nonce              = q["nonce"].ToString();
        var prompt             = q["prompt"].ToString()
                                   .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                   .ToHashSet(StringComparer.Ordinal);
        var maxAgeParam        = q["max_age"].ToString();

        // 1. Validate the request parameters
        var validation = await validator.ValidateAsync(
            clientId, responseType, redirectUri, scope,
            codeChallenge, codeChallengeMethod, ct);

        if (!validation.IsValid)
            return BuildErrorResponse(validation.ValidatedRedirectUri, state, validation.Error!, validation.ErrorDesc!);

        var client           = validation.Client!;
        var trustedRedirect  = validation.ValidatedRedirectUri!;

        // Request objects (JAR) are not supported: reject explicitly instead of silently ignoring
        // parameters that may carry security-relevant values (OIDC Core §6).
        if (q.ContainsKey("request"))
            return BuildErrorResponse(trustedRedirect, state, "request_not_supported", "The request parameter is not supported");
        if (q.ContainsKey("request_uri"))
            return BuildErrorResponse(trustedRedirect, state, "request_uri_not_supported", "The request_uri parameter is not supported");

        // OIDC Core §3.1.2.1: "none" must not be combined with any other prompt value.
        if (prompt.Contains("none") && prompt.Count > 1)
            return BuildErrorResponse(trustedRedirect, state, Constants.OAuthErrors.InvalidRequest, "prompt=none cannot be combined with other values");

        int? maxAge = null;
        if (!string.IsNullOrEmpty(maxAgeParam))
        {
            if (!int.TryParse(maxAgeParam, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var parsed))
                return BuildErrorResponse(trustedRedirect, state, Constants.OAuthErrors.InvalidRequest, "max_age must be a non-negative integer");
            maxAge = parsed;
        }

        // 2. Ensure the user is authenticated (prompt=login / max_age force a new authentication)
        var authResult    = await ctx.AuthenticateAsync();
        var authenticated = authResult.Succeeded && authResult.Principal is not null;
        var authTooOld    = authenticated && maxAge is not null &&
                            authResult.Properties?.IssuedUtc is { } issued &&
                            DateTimeOffset.UtcNow - issued > TimeSpan.FromSeconds(maxAge.Value);

        if (!authenticated || prompt.Contains("login") || authTooOld)
        {
            if (prompt.Contains("none"))
                return BuildErrorResponse(trustedRedirect, state, "login_required", "The user must sign in");

            // returnUrl without prompt=login / max_age, otherwise the user would loop forever
            var returnUrl = BuildReturnUrl(ctx, removePrompt: "login", removeMaxAge: true);
            return Results.Redirect(QueryHelpers.AddQueryString(options.LoginPath, "returnUrl", returnUrl));
        }

        var subjectId = authResult.Principal!.FindFirst("sub")?.Value
                     ?? authResult.Principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(subjectId))
            return BuildErrorResponse(trustedRedirect, state, "server_error", "Could not determine user identity");

        // 2b. Consent (clients with RequireConsent)
        if (client.RequireConsent)
        {
            var consent = await consentStore.GetAsync(subjectId, client.ClientId, ct);
            var hasConsent = consent is not null &&
                             consent.IsValid(DateTime.UtcNow) &&
                             consent.Covers(validation.RequestedScopes) &&
                             !prompt.Contains("consent");

            if (!hasConsent)
            {
                if (prompt.Contains("none"))
                    return BuildErrorResponse(trustedRedirect, state, "consent_required", "The user must consent");

                var returnUrl = BuildReturnUrl(ctx, removePrompt: "consent", removeMaxAge: false);
                return Results.Redirect(QueryHelpers.AddQueryString(options.ConsentPath, "returnUrl", returnUrl));
            }

            // "Allow this time only" consents are used once.
            if (!consent!.Remember)
                await consentStore.RemoveAsync(subjectId, client.ClientId, ct);
        }

        // 3. Issue authorization code
        var authCode = new AuthorizationCode
        {
            Code                = GenerateCode(),
            ClientId            = client.ClientId,
            SubjectId           = subjectId,
            CodeChallenge       = string.IsNullOrEmpty(codeChallenge) ? null : codeChallenge,
            CodeChallengeMethod = string.IsNullOrEmpty(codeChallengeMethod) ? null : codeChallengeMethod,
            Scopes              = validation.RequestedScopes,
            RedirectUri         = string.IsNullOrEmpty(redirectUri) ? null : redirectUri,
            Nonce               = string.IsNullOrEmpty(nonce) ? null : nonce,
            AuthTime            = authResult.Properties?.IssuedUtc?.UtcDateTime,
            // The login decides the authentication level by adding an "acr" claim when signing in
            // (acr_values is only a preference of the client, OIDC Core §3.1.2.1).
            Acr                 = authResult.Principal.FindFirst("acr")?.Value ?? options.DefaultAcr,
            CreatedAt           = DateTime.UtcNow,
            ExpiresAt           = DateTime.UtcNow.AddSeconds(client.AuthorizationCodeLifetime),
        };

        await codeStore.StoreAsync(authCode, ct);

        // 4. Redirect back to client
        var parameters = new Dictionary<string, string?> { ["code"] = authCode.Code };
        if (!string.IsNullOrEmpty(state))
            parameters["state"] = state;

        return Results.Redirect(QueryHelpers.AddQueryString(trustedRedirect, parameters));
    }

    /// <summary>
    /// Returns an authorization error. Redirects to the client ONLY when
    /// <paramref name="validatedRedirectUri"/> has been verified against the client's
    /// registration; otherwise the error is rendered locally (RFC 6749 §4.1.2.1),
    /// so an attacker-supplied redirect_uri can never be used as an open redirect.
    /// </summary>
    private static IResult BuildErrorResponse(string? validatedRedirectUri, string? state, string error, string description)
    {
        if (string.IsNullOrEmpty(validatedRedirectUri))
            return Results.BadRequest(new { error, error_description = description });

        var parameters = new Dictionary<string, string?>
        {
            ["error"]             = error,
            ["error_description"] = description,
        };
        if (!string.IsNullOrEmpty(state))
            parameters["state"] = state;

        return Results.Redirect(QueryHelpers.AddQueryString(validatedRedirectUri, parameters));
    }

    /// <summary>
    /// The current authorize URL (local path + query) without the given prompt value and,
    /// optionally, without max_age — used as returnUrl for the login / consent pages.
    /// </summary>
    private static string BuildReturnUrl(HttpContext ctx, string removePrompt, bool removeMaxAge)
    {
        var parameters = new List<KeyValuePair<string, string?>>();
        foreach (var (key, values) in ctx.Request.Query)
        {
            if (removeMaxAge && key == "max_age")
                continue;

            if (key == "prompt")
            {
                var remaining = string.Join(' ', values.ToString()
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .Where(v => v != removePrompt));
                if (remaining.Length > 0)
                    parameters.Add(new(key, remaining));
                continue;
            }

            foreach (var value in values)
                parameters.Add(new(key, value));
        }

        return QueryHelpers.AddQueryString((ctx.Request.PathBase + ctx.Request.Path).ToString(), parameters);
    }

    private static string GenerateCode()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
