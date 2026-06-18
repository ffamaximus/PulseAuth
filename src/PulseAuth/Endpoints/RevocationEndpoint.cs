using Microsoft.AspNetCore.Http;
using PulseAuth.Abstractions;
using PulseAuth.Constants;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles POST /connect/revocation (RFC 7009)
/// Revokes an access token or refresh token.
/// </summary>
internal static class RevocationEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext              ctx,
        IRefreshTokenStore       refreshTokenStore,
        CancellationToken        ct)
    {
        var form      = ctx.Request.Form;
        var token     = form["token"].ToString();
        var tokenHint = form["token_type_hint"].ToString();

        if (string.IsNullOrEmpty(token))
            return Results.Json(
                new { error = OAuthErrors.InvalidRequest, error_description = "token is required" },
                statusCode: 400);

        // Try to revoke as refresh token
        var rt = await refreshTokenStore.FindByTokenAsync(token, ct);
        if (rt is not null)
            await refreshTokenStore.ConsumeAsync(token, ct);

        // Per RFC 7009 §2.2: always return 200 OK (don't reveal whether token existed)
        return Results.Ok();
    }
}
