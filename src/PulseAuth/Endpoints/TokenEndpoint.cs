using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Constants;
using PulseAuth.Models;
using PulseAuth.Validators;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles POST /connect/token
/// Supports: authorization_code, client_credentials, refresh_token, password (legacy).
/// </summary>
internal static class TokenEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext                ctx,
        IOptions<PulseAuthOptions> optionsAccessor,
        TokenRequestValidator      validator,
        ITokenService              tokenService,
        IAuthorizationCodeStore    codeStore,
        IRefreshTokenStore         refreshTokenStore,
        CancellationToken          ct)
    {
        var options = optionsAccessor.Value;
        var form    = ctx.Request.Form;

        // Support both form-body and Authorization header for client credentials
        ExtractClientCredentials(ctx, form,
            out var clientId, out var clientSecret);

        var grantType     = form["grant_type"].ToString();
        var code          = form["code"].ToString();
        var codeVerifier  = form["code_verifier"].ToString();
        var redirectUri   = form["redirect_uri"].ToString();
        var scope         = form["scope"].ToString();
        var refreshToken  = form["refresh_token"].ToString();
        var username      = form["username"].ToString();
        var password      = form["password"].ToString();
        // Social token-exchange grants (google_id_token, facebook_access_token, etc.)
        var externalToken = form["token"].ToString();

        var validation = await validator.ValidateAsync(
            grantType, clientId, clientSecret,
            code, codeVerifier, redirectUri, scope,
            refreshToken, username, password, externalToken, ct);

        if (!validation.IsValid)
            return Results.Json(
                new { error = validation.Error, error_description = validation.ErrorDesc },
                statusCode: 400);

        var client    = validation.Client!;
        var subject   = validation.SubjectId!;
        var scopes    = validation.Scopes;

        // ── One-time-use enforcement (BEFORE issuing any token) ────────────────
        // The validator only *reads* the grant. Consumption must be an atomic
        // compare-and-set so that two concurrent requests presenting the same
        // code / refresh token can never both receive tokens (replay / race).
        if (grantType == GrantTypes.AuthorizationCode)
        {
            if (!await codeStore.TryConsumeAsync(code, ct))
                return InvalidGrant("Authorization code has already been used");
        }

        var rotatedRefreshToken = false;
        if (grantType == GrantTypes.RefreshToken &&
            validation.RefreshTokenEntity is not null &&
            options.RotateRefreshTokens)
        {
            var grace = options.RefreshTokenReuseGracePeriod;

            // If the validator already saw it consumed, it was accepted inside the grace window.
            if (!validation.RefreshTokenEntity.IsConsumed &&
                !await refreshTokenStore.TryConsumeAsync(refreshToken, grace, ct))
            {
                // Lost a race with a concurrent request: accept only within the grace window.
                var current = await refreshTokenStore.FindByTokenAsync(refreshToken, ct);
                if (current is null || !current.IsWithinReuseGracePeriod(grace, DateTime.UtcNow))
                {
                    if (current is not null)
                    {
                        var logger = ctx.RequestServices.GetService<ILoggerFactory>()?.CreateLogger(typeof(TokenRequestValidator));
                        await TokenRequestValidator.HandleRefreshTokenReuseAsync(
                            refreshTokenStore, current, client.ClientId, logger, ct);
                    }
                    return InvalidGrant("Refresh token has already been used");
                }
            }

            rotatedRefreshToken = true;
        }

        // Create access token
        var accessToken = await tokenService.CreateAccessTokenAsync(subject, client.ClientId, scopes, ct: ct);

        // Create ID token for any user-facing grant (client_credentials has no user identity).
        // CreateIdTokenAsync returns null if openid scope is not present, so it's safe to call always.
        string? idToken = null;
        if (grantType != GrantTypes.ClientCredentials)
        {
            idToken = await tokenService.CreateIdTokenAsync(
                subject, client.ClientId, validation.Nonce, scopes, ct: ct);
        }

        // Handle refresh token
        string? newRefreshToken = null;
        if (grantType != GrantTypes.ClientCredentials &&
            (scopes.Contains(StandardScopes.OfflineAccess) || grantType == GrantTypes.RefreshToken))
        {
            // Old refresh token was already consumed atomically above when rotating;
            // otherwise the same refresh token is returned (no rotation).
            if (grantType == GrantTypes.RefreshToken &&
                validation.RefreshTokenEntity is not null &&
                !rotatedRefreshToken)
            {
                newRefreshToken = refreshToken;
            }

            if (newRefreshToken is null)
            {
                var rt = new RefreshToken
                {
                    Token     = GenerateToken(),
                    ClientId  = client.ClientId,
                    SubjectId = subject,
                    Scopes    = scopes,
                    // Link rotations into a family (hash only — never the raw previous token)
                    // so reuse of an old token can revoke the whole chain.
                    PreviousTokenId = rotatedRefreshToken ? RefreshToken.ComputeTokenId(refreshToken) : null,
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddSeconds(
                        client.RefreshTokenLifetime > 0
                            ? client.RefreshTokenLifetime
                            : options.DefaultRefreshTokenLifetime),
                };
                await refreshTokenStore.StoreAsync(rt, ct);
                newRefreshToken = rt.Token;
            }
        }

        var response = new TokenResponse
        {
            AccessToken  = accessToken,
            TokenType    = "Bearer",
            ExpiresIn    = client.AccessTokenLifetime > 0
                               ? client.AccessTokenLifetime
                               : options.DefaultAccessTokenLifetime,
            RefreshToken = newRefreshToken,
            IdToken      = idToken,
            Scope        = string.Join(" ", scopes),
        };

        return Results.Ok(response);
    }

    private static IResult InvalidGrant(string description)
        => Results.Json(
            new { error = OAuthErrors.InvalidGrant, error_description = description },
            statusCode: 400);

    private static void ExtractClientCredentials(
        HttpContext ctx,
        IFormCollection form,
        out string? clientId,
        out string? clientSecret)
    {
        // Try Authorization: Basic header first
        var authHeader = ctx.Request.Headers.Authorization.ToString();
        if (authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            var decoded = System.Text.Encoding.UTF8.GetString(
                Convert.FromBase64String(authHeader["Basic ".Length..]));
            var parts = decoded.Split(':', 2);
            clientId     = parts.Length > 0 ? Uri.UnescapeDataString(parts[0]) : null;
            clientSecret = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]) : null;
            return;
        }

        // Fall back to form body
        clientId     = form["client_id"].ToString();
        clientSecret = form["client_secret"].ToString();
        if (string.IsNullOrEmpty(clientId)) clientId = null;
        if (string.IsNullOrEmpty(clientSecret)) clientSecret = null;
    }

    private static string GenerateToken()
    {
        var bytes = new byte[64];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
