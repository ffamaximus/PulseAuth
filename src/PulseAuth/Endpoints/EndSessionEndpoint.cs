using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles GET /connect/endsession (OIDC RP-Initiated Logout)
/// Signs out the user and redirects to post_logout_redirect_uri.
/// </summary>
/// <remarks>
/// Security: the post_logout_redirect_uri is only honoured when the requesting client
/// can be identified (via <c>client_id</c> or a valid <c>id_token_hint</c>) AND the URI
/// is registered for that client (exact, ordinal match). Otherwise the user is sent to
/// <see cref="PulseAuthOptions.LogoutPath"/>. This prevents the endpoint from being used
/// as an open redirector.
/// </remarks>
internal static class EndSessionEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext                ctx,
        IOptions<PulseAuthOptions> optionsAccessor,
        IClientStore               clients,
        IRefreshTokenStore         refreshTokens,
        IReferenceTokenStore       referenceTokens,
        IKeyMaterialService        keyMaterial,
        CancellationToken          ct)
    {
        var options = optionsAccessor.Value;

        // OIDC RP-Initiated Logout allows GET (query) and POST (form).
        var parameters = HttpMethods.IsPost(ctx.Request.Method) && ctx.Request.HasFormContentType
            ? (await ctx.Request.ReadFormAsync(ct)).ToDictionary(kv => kv.Key, kv => kv.Value.ToString())
            : ctx.Request.Query.ToDictionary(kv => kv.Key, kv => kv.Value.ToString());

        string Param(string name) => parameters.TryGetValue(name, out var v) ? v : string.Empty;

        var requestedRedirectUri = Param("post_logout_redirect_uri");
        var state                = Param("state");
        var clientId             = Param("client_id");
        var idTokenHint          = Param("id_token_hint");

        // ── 1. Identify the client (client_id and/or id_token_hint) ──────────
        string? hintSubject = null;
        var     clientValid = true;

        if (!string.IsNullOrEmpty(idTokenHint))
        {
            var hint = await ValidateIdTokenHintAsync(idTokenHint, options, keyMaterial, ct);
            if (hint is null)
            {
                clientValid = false; // invalid / forged hint → never redirect
            }
            else
            {
                hintSubject = hint.Value.Subject;

                if (string.IsNullOrEmpty(clientId))
                    clientId = hint.Value.Audience;
                else if (!string.Equals(clientId, hint.Value.Audience, StringComparison.Ordinal))
                    clientValid = false; // client_id does not match the hint's audience
            }
        }

        // ── 2. Validate post_logout_redirect_uri against the client's registration ──
        string? postLogoutRedirectUri = null;
        if (clientValid &&
            !string.IsNullOrEmpty(requestedRedirectUri) &&
            !string.IsNullOrEmpty(clientId))
        {
            var client = await clients.FindClientByIdAsync(clientId, ct);
            if (client is { Enabled: true } &&
                client.PostLogoutRedirectUris.Any(u =>
                    string.Equals(u, requestedRedirectUri, StringComparison.Ordinal)))
            {
                postLogoutRedirectUri = requestedRedirectUri;
            }
        }

        // ── 3. Sign out ──────────────────────────────────────────────────────
        var authResult = await ctx.AuthenticateAsync();
        if (authResult.Succeeded && authResult.Principal is not null)
        {
            var subjectId = authResult.Principal.FindFirst("sub")?.Value
                         ?? authResult.Principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

            // Revoke this client's refresh tokens for the signed-in user. If an
            // id_token_hint was supplied it must belong to the same user.
            var hintMatchesSession = hintSubject is null ||
                                     string.Equals(hintSubject, subjectId, StringComparison.Ordinal);

            // Logout CSRF protection (OIDC RP-Initiated Logout §2): without a valid id_token_hint
            // for the current user, any site could sign the user out with a simple link. When
            // enabled, the user is sent to LogoutPath to confirm; that page signs out (POST with
            // antiforgery) and then redirects back to returnUrl, which completes the flow here.
            var verifiedByHint = hintSubject is not null && hintMatchesSession && clientValid;
            if (options.RequireLogoutConfirmation && !verifiedByHint)
            {
                var returnUrl = QueryHelpers.AddQueryString(
                    ctx.Request.PathBase + ctx.Request.Path,
                    parameters.Where(kv => !string.IsNullOrEmpty(kv.Value))
                              .Select(kv => new KeyValuePair<string, string?>(kv.Key, kv.Value)));

                return Results.Redirect(QueryHelpers.AddQueryString(options.LogoutPath, "returnUrl", returnUrl));
            }

            if (clientValid && hintMatchesSession &&
                !string.IsNullOrEmpty(subjectId) && !string.IsNullOrEmpty(clientId))
            {
                await refreshTokens.RevokeBySubjectAsync(subjectId, clientId, ct);
                await referenceTokens.RemoveBySubjectAsync(subjectId, clientId, ct);
            }
        }

        await ctx.SignOutAsync();

        // ── 4. Redirect ──────────────────────────────────────────────────────
        if (postLogoutRedirectUri is not null)
        {
            var redirect = string.IsNullOrEmpty(state)
                ? postLogoutRedirectUri
                : QueryHelpers.AddQueryString(postLogoutRedirectUri, "state", state);

            return Results.Redirect(redirect);
        }

        return Results.Redirect(options.LogoutPath);
    }

    /// <summary>
    /// Validates an id_token_hint issued by this server. Signature and issuer are
    /// verified; lifetime is NOT (expired ID tokens are valid hints per OIDC RP-Initiated Logout §2).
    /// Returns the token's audience (client_id) and subject, or null if invalid.
    /// </summary>
    private static async Task<(string Audience, string? Subject)?> ValidateIdTokenHintAsync(
        string idTokenHint,
        PulseAuthOptions options,
        IKeyMaterialService keyMaterial,
        CancellationToken ct)
    {
        try
        {
            var keys    = await keyMaterial.GetValidationKeysAsync(ct);
            var handler = new JwtSecurityTokenHandler();

            handler.ValidateToken(idTokenHint, new TokenValidationParameters
            {
                ValidIssuer       = options.Issuer,
                ValidateIssuer    = true,
                ValidateAudience  = false,
                ValidateLifetime  = false,
                IssuerSigningKeys = keys,
            }, out var validated);

            if (validated is not JwtSecurityToken jwt)
                return null;

            var audience = jwt.Audiences.FirstOrDefault();
            if (string.IsNullOrEmpty(audience))
                return null;

            return (audience, jwt.Subject);
        }
        catch (Exception ex) when (ex is SecurityTokenException or ArgumentException)
        {
            return null;
        }
    }
}
