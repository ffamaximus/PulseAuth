using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Constants;

namespace PulseAuth.Services;

/// <summary>
/// Default JWT token service. Issues RS256-signed access tokens and ID tokens.
/// </summary>
public class DefaultTokenService : ITokenService
{
    private readonly IKeyMaterialService _keyMaterial;
    private readonly IUserAuthenticationService _users;
    private readonly PulseAuthOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultTokenService"/> class with the provided dependencies. The token service relies on the <see cref="IKeyMaterialService"/> to obtain signing credentials for creating JWTs, and the <see cref="IUserAuthenticationService"/> to retrieve user information when generating ID tokens. The <see cref="PulseAuthOptions"/> are used to configure token properties such as issuer, audience, and token lifetimes. This default implementation creates access tokens containing standard claims (sub, jti, iat, client_id, scope) and ID tokens containing user profile claims based on the requested scopes (e.g., name, email). For production use, consider implementing a custom token service that supports additional features such as refresh tokens, custom claim transformations or different signing algorithms.
    /// </summary>
    /// <param name="keyMaterial"></param>
    /// <param name="users"></param>
    /// <param name="options"></param>
    public DefaultTokenService(
        IKeyMaterialService keyMaterial,
        IUserAuthenticationService users,
        IOptions<PulseAuthOptions> options)
    {
        _keyMaterial = keyMaterial;
        _users       = users;
        _options     = options.Value;
    }

    /// <inheritdoc />
    public async Task<string> CreateAccessTokenAsync(
        string subjectId,
        string clientId,
        IEnumerable<string> scopes,
        IEnumerable<Claim>? additionalClaims = null,
        CancellationToken ct = default)
    {
        var credentials = await _keyMaterial.GetSigningCredentialsAsync(ct);
        var now         = DateTime.UtcNow;
        var scopeList   = scopes.ToList();

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub,       subjectId),
            new(JwtRegisteredClaimNames.Jti,       Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat,       EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
            new("client_id",                       clientId),
            new("scope",                           string.Join(" ", scopeList)),
        };

        if (additionalClaims is not null)
            claims.AddRange(additionalClaims);

        var token = new JwtSecurityToken(
            issuer:             _options.Issuer,
            audience:           _options.DefaultAudience ?? clientId,
            claims:             claims,
            notBefore:          now,
            expires:            now.AddSeconds(_options.DefaultAccessTokenLifetime),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <inheritdoc />
    public async Task<string?> CreateIdTokenAsync(
        string subjectId,
        string clientId,
        string? nonce,
        IEnumerable<string> scopes,
        IEnumerable<Claim>? additionalClaims = null,
        CancellationToken ct = default)
    {
        var scopeList = scopes.ToList();

        // ID tokens are only issued when openid scope is present
        if (!scopeList.Contains(StandardScopes.OpenId))
            return null;

        var credentials = await _keyMaterial.GetSigningCredentialsAsync(ct);
        var now         = DateTime.UtcNow;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub,      subjectId),
            new(JwtRegisteredClaimNames.Jti,      Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat,      EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.AuthTime, EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
        };

        if (!string.IsNullOrEmpty(nonce))
            claims.Add(new(JwtRegisteredClaimNames.Nonce, nonce));

        // Add profile claims based on requested scopes
        var user = await _users.GetUserByIdAsync(subjectId, ct);
        if (user is not null)
        {
            if (scopeList.Contains(StandardScopes.Profile))
            {
                AddIfNotNull(claims, JwtRegisteredClaimNames.Name,         user.Name);
                AddIfNotNull(claims, JwtRegisteredClaimNames.GivenName,    user.GivenName);
                AddIfNotNull(claims, JwtRegisteredClaimNames.FamilyName,   user.FamilyName);
                AddIfNotNull(claims, "picture",                             user.Picture);
                AddIfNotNull(claims, "preferred_username",                  user.Username);
            }
            if (scopeList.Contains(StandardScopes.Email))
            {
                AddIfNotNull(claims, JwtRegisteredClaimNames.Email,        user.Email);
                claims.Add(new("email_verified", user.EmailVerified.ToString().ToLower(), ClaimValueTypes.Boolean));
            }
            if (scopeList.Contains(StandardScopes.Phone))
            {
                AddIfNotNull(claims, "phone_number",          user.PhoneNumber);
                claims.Add(new("phone_number_verified", user.PhoneNumberVerified.ToString().ToLower(), ClaimValueTypes.Boolean));
            }

            claims.AddRange(user.AdditionalClaims);
        }

        if (additionalClaims is not null)
            claims.AddRange(additionalClaims);

        var token = new JwtSecurityToken(
            issuer:             _options.Issuer,
            audience:           clientId,
            claims:             claims,
            notBefore:          now,
            expires:            now.AddSeconds(_options.DefaultIdentityTokenLifetime),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static void AddIfNotNull(List<Claim> claims, string type, string? value)
    {
        if (!string.IsNullOrEmpty(value))
            claims.Add(new(type, value));
    }
}
