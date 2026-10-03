using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PulseAuth.Abstractions;
using PulseAuth.Helpers;
using PulseAuth.Services;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles POST /connect/introspect (RFC 7662).
/// </summary>
/// <remarks>
/// <para>The caller must be a <b>confidential</b> client (client_secret_basic / client_secret_post).</para>
/// <para>
/// Access tokens (JWT or reference): a client with <c>AllowIntrospection</c> (an API / resource
/// server) may introspect any token; other clients only tokens issued to themselves.
/// Refresh tokens: only the client they were issued to.
/// </para>
/// <para>Anything invalid, expired, revoked or not visible to the caller returns <c>{"active": false}</c>.</para>
/// </remarks>
internal static class IntrospectionEndpoint
{
    private static readonly object Inactive = new { active = false };

    public static async Task<IResult> HandleAsync(
        HttpContext          ctx,
        IClientStore         clients,
        AccessTokenValidator accessTokens,
        IRefreshTokenStore   refreshTokens,
        CancellationToken    ct)
    {
        if (!ctx.Request.HasFormContentType)
            return ClientCredentialsReader.NotAForm();

        var form = await ctx.Request.ReadFormAsync(ct);

        // ── 1. Authenticate the caller (must be confidential) ─────────────────
        var credentials = ClientCredentialsReader.Read(ctx, form);
        if (!credentials.IsValid || credentials.ClientId is null || credentials.ClientSecret is null)
            return ClientCredentialsReader.InvalidClient(ctx, credentials.UsedBasic, "Client authentication failed");

        var caller = await clients.FindClientByIdAsync(credentials.ClientId, ct);
        if (caller is null || !caller.Enabled || string.IsNullOrEmpty(caller.ClientSecretHash) ||
            !ClientSecretHelper.Verify(credentials.ClientSecret, caller.ClientSecretHash))
            return ClientCredentialsReader.InvalidClient(ctx, credentials.UsedBasic, "Client authentication failed");

        var token = form["token"].ToString();
        if (string.IsNullOrEmpty(token))
            return Results.Json(new { error = "invalid_request", error_description = "token is required" }, statusCode: 400);

        var hint = form["token_type_hint"].ToString();
        ctx.Response.Headers.CacheControl = "no-store";

        // ── 2. Refresh token (by hint, or when it is not an access token) ─────
        if (hint == "refresh_token")
            return await IntrospectRefreshTokenAsync(token, caller.ClientId, refreshTokens, ct)
                   ?? await IntrospectAccessTokenAsync(ctx, token, caller, accessTokens, ct)
                   ?? Results.Json(Inactive);

        return await IntrospectAccessTokenAsync(ctx, token, caller, accessTokens, ct, allowInactive: false)
               ?? await IntrospectRefreshTokenAsync(token, caller.ClientId, refreshTokens, ct)
               ?? Results.Json(Inactive);
    }

    private static async Task<IResult?> IntrospectAccessTokenAsync(
        HttpContext ctx, string token, Models.Client caller, AccessTokenValidator accessTokens,
        CancellationToken ct, bool allowInactive = true)
    {
        var result = await accessTokens.ValidateAsync(token, ct);
        if (!result.IsValid ||
            (!caller.AllowIntrospection && !string.Equals(result.ClientId, caller.ClientId, StringComparison.Ordinal)))
        {
            return allowInactive ? Results.Json(Inactive) : null;
        }

        // RFC 7662 §2.2: return the token's claims plus "active" and "token_type".
        var response = new Dictionary<string, object?>();
        foreach (var (name, value) in result.Token!.Payload)
            response[name] = value is JsonElement json ? json.Clone() : value;

        response["active"]     = true;
        response["token_type"] = "access_token";
        response["username"]   = result.Token.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
        if (response["username"] is null)
            response.Remove("username");

        ctx.RequestServices.GetService<ILoggerFactory>()?.CreateLogger("PulseAuth.IntrospectionEndpoint")
            .LogDebug("Access token introspected by {Caller} (issued to {ClientId}, reference: {IsReference})",
                caller.ClientId, result.ClientId, result.IsReferenceToken);

        return Results.Json(response);
    }

    private static async Task<IResult?> IntrospectRefreshTokenAsync(
        string token, string callerClientId, IRefreshTokenStore refreshTokens, CancellationToken ct)
    {
        var rt = await refreshTokens.FindByTokenAsync(token, ct);
        if (rt is null || !string.Equals(rt.ClientId, callerClientId, StringComparison.Ordinal))
            return null;

        if (rt.IsConsumed || rt.ExpiresAt <= DateTime.UtcNow)
            return Results.Json(Inactive);

        return Results.Json(new Dictionary<string, object?>
        {
            ["active"]     = true,
            ["token_type"] = "refresh_token",
            ["client_id"]  = rt.ClientId,
            ["sub"]        = rt.SubjectId,
            ["scope"]      = string.Join(" ", rt.Scopes),
            ["iat"]        = new DateTimeOffset(DateTime.SpecifyKind(rt.CreatedAt, DateTimeKind.Utc)).ToUnixTimeSeconds(),
            ["exp"]        = new DateTimeOffset(DateTime.SpecifyKind(rt.ExpiresAt, DateTimeKind.Utc)).ToUnixTimeSeconds(),
        });
    }
}
