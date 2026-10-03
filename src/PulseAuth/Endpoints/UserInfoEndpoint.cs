using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Constants;
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
        IKeyMaterialService           keyMaterial,
        IUserAuthenticationService    users,
        CancellationToken             ct)
    {
        var options = optionsAccessor.Value;

        // Extract bearer token
        var authHeader = ctx.Request.Headers.Authorization.ToString();
        if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Results.Unauthorized();

        var token = authHeader["Bearer ".Length..].Trim();

        // Validate the JWT
        var validationKeys = await keyMaterial.GetValidationKeysAsync(ct);
        var handler        = new JwtSecurityTokenHandler();

        ClaimsPrincipal principal;
        SecurityToken   validatedToken;
        try
        {
            principal = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer          = options.Issuer,
                ValidateIssuer       = true,
                ValidateAudience     = false,
                ValidateLifetime     = true,
                IssuerSigningKeys    = validationKeys,
                ClockSkew            = TimeSpan.FromSeconds(30),
            }, out validatedToken);
        }
        catch (Exception ex) when (ex is SecurityTokenException or ArgumentException)
        {
            return Results.Json(
                new { error = OAuthErrors.InvalidToken, error_description = "Token validation failed" },
                statusCode: 401);
        }

        // Only ACCESS tokens may call userinfo — never an ID token (token confusion).
        // Current access tokens carry typ "at+jwt" (RFC 9068). Tokens issued by PulseAuth <= 1.2.x
        // use "JWT"; they are recognised by the client_id claim, which ID tokens never contain.
        if (!IsAccessToken(validatedToken))
        {
            return Results.Json(
                new { error = OAuthErrors.InvalidToken, error_description = "An access token is required" },
                statusCode: 401);
        }

        var subjectId = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                     ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(subjectId))
            return Results.Unauthorized();

        var user = await users.GetUserByIdAsync(subjectId, ct);
        if (user is null)
            return Results.Unauthorized();

        // Build userinfo response — only include claims for granted scopes
        var scopeClaim = principal.FindFirst("scope")?.Value ?? "";
        var scopes     = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var result = new Dictionary<string, object?> { ["sub"] = user.SubjectId };

        if (scopes.Contains(StandardScopes.Profile))
        {
            AddIfNotNull(result, "name",               user.Name);
            AddIfNotNull(result, "given_name",         user.GivenName);
            AddIfNotNull(result, "family_name",        user.FamilyName);
            AddIfNotNull(result, "picture",            user.Picture);
            AddIfNotNull(result, "preferred_username", user.Username);
        }

        if (scopes.Contains(StandardScopes.Email))
        {
            AddIfNotNull(result, "email", user.Email);
            result["email_verified"] = user.EmailVerified;
        }

        if (scopes.Contains(StandardScopes.Phone))
        {
            AddIfNotNull(result, "phone_number", user.PhoneNumber);
            result["phone_number_verified"] = user.PhoneNumberVerified;
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

    private static bool IsAccessToken(SecurityToken token)
    {
        if (token is not JwtSecurityToken jwt)
            return false;

        if (string.Equals(jwt.Header.Typ, DefaultTokenService.AccessTokenType, StringComparison.OrdinalIgnoreCase))
            return true;

        // Legacy access tokens (typ "JWT"): identified by the client_id claim.
        return jwt.Claims.Any(c => c.Type == "client_id");
    }

    private static void AddIfNotNull(Dictionary<string, object?> dict, string key, string? value)
    {
        if (!string.IsNullOrEmpty(value))
            dict[key] = value;
    }
}
