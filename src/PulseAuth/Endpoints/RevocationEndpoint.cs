using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PulseAuth.Abstractions;
using PulseAuth.Constants;
using PulseAuth.Helpers;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles POST /connect/revocation (RFC 7009).
/// </summary>
/// <remarks>
/// The client must authenticate (confidential clients) or identify itself with
/// <c>client_id</c> (public clients), and can only revoke tokens that were issued to it.
/// Refresh tokens and reference access tokens are revoked. JWT access tokens are self-contained and
/// cannot be revoked: the request succeeds but has no effect (keep their lifetime short, or use
/// <c>AccessTokenType.Reference</c> for clients that need revocable access tokens).
/// </remarks>
internal static class RevocationEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext              ctx,
        IClientStore             clients,
        IRefreshTokenStore       refreshTokenStore,
        IReferenceTokenStore     referenceTokenStore,
        Services.AccessTokenValidator accessTokens,
        IRevokedTokenStore       revokedTokens,
        CancellationToken        ct)
    {
        if (!ctx.Request.HasFormContentType)
            return ClientCredentialsReader.NotAForm();

        var form = await ctx.Request.ReadFormAsync(ct);

        // ── 1. Client authentication (RFC 7009 §2.1) ─────────────────────────
        var credentials = ClientCredentialsReader.Read(ctx, form);
        if (!credentials.IsValid || string.IsNullOrEmpty(credentials.ClientId))
            return ClientCredentialsReader.InvalidClient(ctx, credentials.UsedBasic, "Client authentication failed");

        var client = await clients.FindClientByIdAsync(credentials.ClientId, ct);
        if (client is null || !client.Enabled)
            return ClientCredentialsReader.InvalidClient(ctx, credentials.UsedBasic, "Client authentication failed");

        if (!string.IsNullOrEmpty(client.ClientSecretHash) &&
            (credentials.ClientSecret is null || !ClientSecretHelper.Verify(credentials.ClientSecret, client.ClientSecretHash)))
            return ClientCredentialsReader.InvalidClient(ctx, credentials.UsedBasic, "Client authentication failed");

        // ── 2. Revoke ───────────────────────────────────────────────────────
        var token = form["token"].ToString();
        if (string.IsNullOrEmpty(token))
            return Results.Json(
                new { error = OAuthErrors.InvalidRequest, error_description = "token is required" },
                statusCode: 400);

        var logger = ctx.RequestServices.GetService<ILoggerFactory>()?.CreateLogger("PulseAuth.RevocationEndpoint");

        // Reference (opaque) access token
        var reference = await referenceTokenStore.FindAsync(token, ct);
        if (reference is not null && string.Equals(reference.ClientId, client.ClientId, StringComparison.Ordinal))
        {
            await referenceTokenStore.RemoveAsync(token, ct);
            logger?.LogInformation("Reference access token revoked by client {ClientId} (subject {SubjectId})", client.ClientId, reference.SubjectId);
            return Results.Ok();
        }

        // JWT access token: add its jti to the deny-list until it expires. Only effective where the list
        // is consulted (UserInfo, introspection) — APIs validating JWTs locally do not see it.
        if (token.Count(c => c == '.') == 2)
        {
            var jwt = await accessTokens.ValidateAsync(token, ct);
            if (jwt.IsValid && jwt.Token is { } at && !string.IsNullOrEmpty(at.Id) &&
                string.Equals(jwt.ClientId, client.ClientId, StringComparison.Ordinal))
            {
                await revokedTokens.RevokeAsync(at.Id, at.ValidTo, ct);
                logger?.LogInformation("JWT access token revoked by client {ClientId} (subject {SubjectId})", client.ClientId, jwt.SubjectId);
            }
            return Results.Ok();
        }

        var rt = await refreshTokenStore.FindByTokenAsync(token, ct);

        // Only the client the token was issued to may revoke it. For any other client — or an
        // unknown / access token — respond 200 without revealing anything (RFC 7009 §2.2).
        if (rt is not null && string.Equals(rt.ClientId, client.ClientId, StringComparison.Ordinal))
        {
            await refreshTokenStore.ConsumeAsync(token, ct);
            logger?.LogInformation("Refresh token revoked by client {ClientId} (subject {SubjectId})", client.ClientId, rt.SubjectId);
        }

        return Results.Ok();
    }
}
