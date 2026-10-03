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

        if (!ctx.Request.HasFormContentType)
            return ClientCredentialsReader.NotAForm();

        var form = await ctx.Request.ReadFormAsync(ct);

        // Support both form-body and Authorization header for client credentials
        var credentials = ClientCredentialsReader.Read(ctx, form);
        if (!credentials.IsValid)
            return ClientCredentialsReader.InvalidClient(ctx, credentials.UsedBasic, "Malformed client credentials");

        var clientId     = credentials.ClientId;
        var clientSecret = credentials.ClientSecret;

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
        {
            Logger(ctx)?.LogInformation(
                "Token request rejected: {Error} ({Description}) client={ClientId} grant_type={GrantType}",
                validation.Error, validation.ErrorDesc, clientId, grantType);

            if (validation.Error == OAuthErrors.InvalidClient)
                return ClientCredentialsReader.InvalidClient(ctx, credentials.UsedBasic, validation.ErrorDesc ?? "Invalid client");

            return Results.Json(
                new { error = validation.Error, error_description = validation.ErrorDesc },
                statusCode: 400);
        }

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
            // (Use the validation-time snapshot: a store may return live objects that another
            // concurrent request has modified since.)
            if (!validation.IsRefreshTokenReuseWithinGracePeriod &&
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
        // client_credentials tokens carry the client's own claims (Client.Claims); protocol claims
        // can never be overridden this way.
        List<System.Security.Claims.Claim>? accessTokenClaims = null;
        if (grantType == GrantTypes.ClientCredentials && client.Claims.Count > 0)
        {
            accessTokenClaims = client.Claims
                .Where(c => !Services.DefaultTokenService.ReservedClaimTypes.Contains(c.Key))
                .Select(c => new System.Security.Claims.Claim(c.Key, c.Value))
                .ToList();
        }

        var accessToken = await tokenService.CreateAccessTokenAsync(subject, client.ClientId, scopes, accessTokenClaims, ct);

        // Create ID token for any user-facing grant (client_credentials has no user identity).
        // CreateIdTokenAsync returns null if openid scope is not present, so it's safe to call always.
        string? idToken = null;
        if (grantType != GrantTypes.ClientCredentials)
        {
            // auth_time = when the user authenticated. Known for grants that authenticate the user
            // in this very request (password, social token exchange); omitted otherwise.
            List<System.Security.Claims.Claim>? idTokenClaims = null;
            if (grantType != GrantTypes.AuthorizationCode && grantType != GrantTypes.RefreshToken)
            {
                idTokenClaims =
                [
                    new(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.AuthTime,
                        DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                        System.Security.Claims.ClaimValueTypes.Integer64),
                ];
            }

            idToken = await tokenService.CreateIdTokenAsync(
                subject, client.ClientId, validation.Nonce, scopes, idTokenClaims, ct);
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

    private static ILogger? Logger(HttpContext ctx)
        => ctx.RequestServices.GetService<ILoggerFactory>()?.CreateLogger("PulseAuth.TokenEndpoint");

    private static string GenerateToken()
    {
        var bytes = new byte[64];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
