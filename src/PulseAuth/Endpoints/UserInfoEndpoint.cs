using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Constants;
using PulseAuth.Helpers;
using PulseAuth.Services;

namespace PulseAuth.Endpoints;

/// <summary>
/// Handles GET /connect/userinfo
/// Returns user claims for a valid Bearer access token.
/// </summary>
internal static class UserInfoEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext                   ctx,
        IOptions<PulseAuthOptions>    optionsAccessor,
        AccessTokenValidator          accessTokens,
        IUserAuthenticationService    users,
        CancellationToken             ct)
    {
        var options = optionsAccessor.Value;

        ctx.Response.Headers.CacheControl = "no-store";

        // Bearer token: Authorization header (RFC 6750 §2.1) or, for POST, the form body (§2.2).
        string? token = null;
        var authHeader = ctx.Request.Headers.Authorization.ToString();
        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            token = authHeader["Bearer ".Length..].Trim();

        if (HttpMethods.IsPost(ctx.Request.Method) && ctx.Request.HasFormContentType)
        {
            var bodyToken = (await ctx.Request.ReadFormAsync(ct))["access_token"].ToString();
            if (!string.IsNullOrEmpty(bodyToken))
            {
                // Clients MUST NOT use more than one method (RFC 6750 §2).
                if (token is not null)
                    return BearerError(400, OAuthErrors.InvalidRequest, "Use only one method to send the access token");
                token = bodyToken;
            }
        }

        if (string.IsNullOrEmpty(token))
        {
            // No credentials at all: plain challenge without error code (RFC 6750 §3.1).
            ctx.Response.Headers.WWWAuthenticate = "Bearer";
            return Results.Unauthorized();
        }

        // Validate the access token (JWT or reference token). ID tokens are rejected.
        var validation = await accessTokens.ValidateAsync(token, ct);
        if (!validation.IsValid)
            return BearerError(401, OAuthErrors.InvalidToken, validation.Error ?? "Invalid access token");

        var principal = validation.Principal!;

        var subjectId = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                     ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(subjectId))
            return BearerError(401, OAuthErrors.InvalidToken, "The access token has no subject");

        var user = await users.GetUserByIdAsync(subjectId, ct);
        if (user is null)
            return BearerError(401, OAuthErrors.InvalidToken, "Unknown user");

        // Build userinfo response — only include claims for granted scopes
        var scopeClaim = principal.FindFirst("scope")?.Value ?? "";
        var scopes     = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var result = new Dictionary<string, object?> { ["sub"] = user.SubjectId };

        // Standard claims released by the granted scopes (OIDC Core §5.4) plus the ones requested
        // individually with the "claims" parameter (§5.5; restricted to allowed scopes at /authorize).
        var requested = (principal.FindFirst(DefaultTokenService.UserInfoClaimsClaimType)?.Value ?? "")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var claimNames = scopes.SelectMany(StandardClaims.ForScope).Concat(requested).Distinct(StringComparer.Ordinal);

        foreach (var name in claimNames)
        {
            if (StandardClaims.GetValue(user, name) is { } value)
                result[name] = value;   // strings, booleans, updated_at as a number, address as an object
        }

        // Additional application claims. Protocol / standard claims already in the response
        // (sub, email, ...) can never be overridden, and repeated types (e.g. several roles)
        // are returned as arrays instead of keeping only the last value.
        foreach (var group in user.AdditionalClaims
                     .Where(c => !DefaultTokenService.ReservedClaimTypes.Contains(c.Type) && !result.ContainsKey(c.Type))
                     .GroupBy(c => c.Type))
        {
            var values = group.Select(c => c.Value).ToArray();
            result[group.Key] = values.Length == 1 ? values[0] : values;
        }

        return Results.Ok(result);
    }

    /// <summary>RFC 6750 §3 error with a <c>WWW-Authenticate: Bearer</c> challenge.</summary>
    private static IResult BearerError(int statusCode, string error, string description)
        => new BearerErrorResult(statusCode, error, description);

    private sealed class BearerErrorResult(int statusCode, string error, string description) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            var safeDescription = description.Replace("\\", "").Replace("\"", "'").Replace('\r', ' ').Replace('\n', ' ');
            httpContext.Response.Headers.WWWAuthenticate =
                $"Bearer error=\"{error}\", error_description=\"{safeDescription}\"";
            return Results.Json(new { error, error_description = description }, statusCode: statusCode)
                          .ExecuteAsync(httpContext);
        }
    }
}
