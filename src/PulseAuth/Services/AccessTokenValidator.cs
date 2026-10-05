using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;

namespace PulseAuth.Services;

/// <summary>Result of <see cref="AccessTokenValidator.ValidateAsync"/>.</summary>
public sealed record AccessTokenValidationResult(
    bool IsValid,
    JwtSecurityToken? Token = null,
    ClaimsPrincipal? Principal = null,
    bool IsReferenceToken = false,
    string? Error = null)
{
    /// <summary>The <c>client_id</c> the token was issued to.</summary>
    public string? ClientId => Token?.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value;

    /// <summary>The <c>sub</c> claim.</summary>
    public string? SubjectId => Token?.Subject;

    internal static AccessTokenValidationResult Invalid(string error) => new(false, Error: error);
}

/// <summary>
/// Validates access tokens issued by this server — JWTs and reference (opaque) tokens — for the
/// userinfo and introspection endpoints. ID tokens are never accepted as access tokens.
/// </summary>
public class AccessTokenValidator
{
    private readonly PulseAuthOptions      _options;
    private readonly IKeyMaterialService   _keys;
    private readonly IReferenceTokenStore? _referenceTokens;
    private readonly IRevokedTokenStore?   _revokedTokens;

    /// <summary>Initializes a new instance of the <see cref="AccessTokenValidator"/> class.</summary>
    public AccessTokenValidator(
        IOptions<PulseAuthOptions> options,
        IKeyMaterialService keys,
        IReferenceTokenStore? referenceTokens = null,
        IRevokedTokenStore? revokedTokens = null)
    {
        _revokedTokens   = revokedTokens;
        _options         = options.Value;
        _keys            = keys;
        _referenceTokens = referenceTokens;
    }

    /// <summary>Validates <paramref name="token"/> (JWT or reference handle).</summary>
    public async Task<AccessTokenValidationResult> ValidateAsync(string token, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return AccessTokenValidationResult.Invalid("Token is empty");

        var jwtText     = token;
        var isReference = false;

        // A JWT has exactly two dots; a reference handle is a base64url string without dots.
        if (token.Count(c => c == '.') != 2)
        {
            if (_referenceTokens is null)
                return AccessTokenValidationResult.Invalid("Unknown token");

            var reference = await _referenceTokens.FindAsync(token, ct);
            if (reference is null || reference.ExpiresAt <= DateTime.UtcNow)
                return AccessTokenValidationResult.Invalid("Unknown, expired or revoked token");

            jwtText     = reference.Jwt;
            isReference = true;
        }

        var handler = new JwtSecurityTokenHandler();
        try
        {
            var principal = handler.ValidateToken(jwtText, new TokenValidationParameters
            {
                ValidIssuer       = _options.Issuer,
                ValidateIssuer    = true,
                ValidateAudience  = false,
                ValidateLifetime  = true,
                IssuerSigningKeys = await _keys.GetValidationKeysAsync(ct),
                ClockSkew         = TimeSpan.FromSeconds(30),
            }, out var validated);

            if (validated is not JwtSecurityToken jwt || !IsAccessToken(jwt))
                return AccessTokenValidationResult.Invalid("An access token is required");

            // Revoked JWTs (revocation endpoint, authorization code replay) — RFC 7009 / RFC 6749 §4.1.2.
            if (_revokedTokens is not null && !string.IsNullOrEmpty(jwt.Id) &&
                await _revokedTokens.IsRevokedAsync(jwt.Id, ct))
                return AccessTokenValidationResult.Invalid("The access token has been revoked");

            return new AccessTokenValidationResult(true, jwt, principal, isReference);
        }
        catch (Exception ex) when (ex is SecurityTokenException or ArgumentException)
        {
            return AccessTokenValidationResult.Invalid("Token validation failed");
        }
    }

    /// <summary>
    /// Access tokens carry typ "at+jwt" (RFC 9068). Tokens issued by PulseAuth ≤ 1.2.x use "JWT" and
    /// are recognised by the client_id claim, which ID tokens never contain.
    /// </summary>
    internal static bool IsAccessToken(JwtSecurityToken jwt)
        => string.Equals(jwt.Header.Typ, DefaultTokenService.AccessTokenType, StringComparison.OrdinalIgnoreCase)
           || jwt.Claims.Any(c => c.Type == "client_id");
}
