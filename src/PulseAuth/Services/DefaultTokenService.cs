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
    private readonly IClientStore? _clients;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultTokenService"/> class with the provided dependencies. The token service relies on the <see cref="IKeyMaterialService"/> to obtain signing credentials for creating JWTs, and the <see cref="IUserAuthenticationService"/> to retrieve user information when generating ID tokens. The <see cref="PulseAuthOptions"/> are used to configure token properties such as issuer, audience, and token lifetimes. This default implementation creates access tokens containing standard claims (sub, jti, iat, client_id, scope) and ID tokens containing user profile claims based on the requested scopes (e.g., name, email). For production use, consider implementing a custom token service that supports additional features such as refresh tokens, custom claim transformations or different signing algorithms.
    /// </summary>
    /// <param name="keyMaterial"></param>
    /// <param name="users"></param>
    /// <param name="options"></param>
    /// <param name="clients">Client store, used to apply per-client token lifetimes.</param>
    public DefaultTokenService(
        IKeyMaterialService keyMaterial,
        IUserAuthenticationService users,
        IOptions<PulseAuthOptions> options,
        IClientStore? clients = null)
    {
        _keyMaterial = keyMaterial;
        _users       = users;
        _options     = options.Value;
        _clients     = clients;
    }

    // Per-client lifetime when configured (> 0), otherwise the global default. The token
    // endpoint uses the same rule for "expires_in", so the response and the JWT always agree.
    private async Task<(int AccessToken, int IdentityToken)> GetLifetimesAsync(string clientId, CancellationToken ct)
    {
        var client = _clients is null ? null : await _clients.FindClientByIdAsync(clientId, ct);
        return (
            client is { AccessTokenLifetime: > 0 }   ? client.AccessTokenLifetime   : _options.DefaultAccessTokenLifetime,
            client is { IdentityTokenLifetime: > 0 } ? client.IdentityTokenLifetime : _options.DefaultIdentityTokenLifetime);
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

        // The caller may fix the jti (the token endpoint does for code exchanges, so a replayed code
        // can revoke the token); otherwise a random one is used.
        var extra = additionalClaims?.ToList();
        var jti   = extra?.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value ?? Guid.NewGuid().ToString();
        extra?.RemoveAll(c => c.Type == JwtRegisteredClaimNames.Jti);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub,       subjectId),
            new(JwtRegisteredClaimNames.Jti,       jti),
            new(JwtRegisteredClaimNames.Iat,       EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
            new("client_id",                       clientId),
            new("scope",                           string.Join(" ", scopeList)),
        };

        // Include user's additional claims (roles, custom claims) in the access token
        // so microservices can make authorization decisions without calling back to the auth server.
        // Returns null for client_credentials (subjectId = clientId, no matching user).
        var user = await _users.GetUserByIdAsync(subjectId, ct);
        if (user?.AdditionalClaims is { Count: > 0 })
            claims.AddRange(WithoutReservedClaims(user.AdditionalClaims));

        if (extra is not null)
            claims.AddRange(extra);

        var token = new JwtSecurityToken(
            issuer:             _options.Issuer,
            audience:           _options.DefaultAudience ?? clientId,
            claims:             claims,
            notBefore:          now,
            expires:            now.AddSeconds((await GetLifetimesAsync(clientId, ct)).AccessToken),
            signingCredentials: credentials);

        // RFC 9068: mark access tokens explicitly so they can never be confused with ID tokens
        // (e.g. an id_token presented as a bearer token to /connect/userinfo or to an API).
        token.Header[JwtHeaderParameterNames.Typ] = AccessTokenType;

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
            // auth_time is NOT set here: it must be the time the user actually authenticated, which
            // only the caller knows (the token endpoint passes it for password / social grants).
        };

        if (!string.IsNullOrEmpty(nonce))
            claims.Add(new(JwtRegisteredClaimNames.Nonce, nonce));

        // Add profile claims based on requested scopes
        var user = await _users.GetUserByIdAsync(subjectId, ct);
        if (user is not null)
        {
            if (_options.IncludeScopeClaimsInIdToken)
                AddScopeClaims(claims, user, scopeList);

            claims.AddRange(WithoutReservedClaims(user.AdditionalClaims));
        }

        if (additionalClaims is not null)
            claims.AddRange(additionalClaims);

        var token = new JwtSecurityToken(
            issuer:             _options.Issuer,
            audience:           clientId,
            claims:             claims,
            notBefore:          now,
            expires:            now.AddSeconds((await GetLifetimesAsync(clientId, ct)).IdentityToken),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Access token claim listing the standard claims requested for UserInfo with the OIDC
    /// <c>claims</c> parameter (space separated). Reserved: user claims can never set it.
    /// </summary>
    public const string UserInfoClaimsClaimType = "userinfo_claims";

    /// <summary>The claim types <see cref="AddScopeClaims"/> puts in the ID token for these scopes.</summary>
    public static IReadOnlySet<string> ScopeClaimTypesInIdToken(IEnumerable<string> scopes)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var scope in scopes)
        {
            switch (scope)
            {
                case StandardScopes.Profile: set.UnionWith(["name", "given_name", "family_name", "picture", "preferred_username"]); break;
                case StandardScopes.Email:   set.UnionWith(["email", "email_verified"]); break;
                case StandardScopes.Phone:   set.UnionWith(["phone_number", "phone_number_verified"]); break;
                case StandardScopes.Address: set.Add("address"); break;
            }
        }
        return set;
    }

    /// <summary>Standard claims of the profile / email / phone scopes (OIDC Core §5.4).</summary>
    private static void AddScopeClaims(List<Claim> claims, Models.UserInfo user, List<string> scopeList)
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
        if (scopeList.Contains(StandardScopes.Address) && user.Address?.ToClaimObject() is { Count: > 0 } address)
        {
            // JSON claim value type → serialized as a nested object in the JWT
            claims.Add(new("address", System.Text.Json.JsonSerializer.Serialize(address), JsonClaimValueTypes.Json));
        }
    }

    /// <summary>JOSE "typ" header value for JWT access tokens (RFC 9068).</summary>
    public const string AccessTokenType = "at+jwt";

    /// <summary>
    /// Protocol claims that user-supplied claims (user.AdditionalClaims, e.g. rows in
    /// AspNetUserClaims) must never set or duplicate: otherwise a user/admin-editable claim
    /// could impersonate another subject (<c>sub</c>), extend scopes, change the audience, etc.
    /// </summary>
    public static readonly IReadOnlySet<string> ReservedClaimTypes = new HashSet<string>(StringComparer.Ordinal)
    {
        "sub", "iss", "aud", "exp", "nbf", "iat", "jti", "client_id", "scope", "nonce",
        "auth_time", "azp", "at_hash", "c_hash", "sid", "cnf", "typ", "acr", UserInfoClaimsClaimType,
        ClaimTypes.NameIdentifier,
    };

    private static IEnumerable<Claim> WithoutReservedClaims(IEnumerable<Claim> claims)
        => claims.Where(c => !ReservedClaimTypes.Contains(c.Type));

    private static void AddIfNotNull(List<Claim> claims, string type, string? value)
    {
        if (!string.IsNullOrEmpty(value))
            claims.Add(new(type, value));
    }
}
