using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Constants;
using PulseAuth.Models;

namespace PulseAuth.Validators;

/// <summary>
/// Result of a token request validation. Contains information about whether the request is valid, any errors that occurred during validation, and if valid, the client, subject ID, scopes, nonce and refresh token entity associated with the request. This result is used by the token endpoint to determine how to proceed with processing the token request (e.g., issuing tokens or returning an error response). The IsValid property indicates whether the validation was successful, while the Error and ErrorDesc properties provide details about any validation failures. If IsValid is true, the Client, SubjectId, Scopes, Nonce and RefreshTokenEntity properties will contain the relevant information extracted from the token request for further processing.
/// </summary>
public class TokenValidationResult
{
    /// <summary>
    /// Indicates whether the token request is valid. If false, the Error and ErrorDesc properties will contain details about the validation failure, which should be returned to the client in the error response. If true, the Client, SubjectId, Scopes, Nonce and RefreshTokenEntity properties will contain the validated information that can be used to proceed with issuing tokens or performing other actions as needed.
    /// </summary>
    public bool IsValid        { get; private init; }
    /// <summary>
    /// If IsValid is false, this property contains the OAuth2 error code that describes the reason for the validation failure. The value should be one of the standard error codes defined in RFC 6749 (e.g., "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope") or a custom error code if needed. This value will be included in the error response sent back to the client.
    /// </summary>
    public string? Error       { get; private init; }
    /// <summary>
    /// If IsValid is false, this property contains a human-readable description of the error that occurred during validation. This description can provide additional context or details about the error to help the client understand what went wrong. This value will be included in the error response sent back to the client, typically in the "error_description" field of the JSON response body.
    /// </summary>
    public string? ErrorDesc   { get; private init; }
    /// <summary>
    /// If IsValid is true, this property contains the Client object that was successfully validated based on the client_id provided in the token request. This object includes all relevant information about the client (e.g., allowed grant types, allowed scopes) that can be used in subsequent steps of the token issuance process. If IsValid is false, this property will be null.
    /// </summary>
    public Client? Client      { get; private init; }
    /// <summary>
    /// If IsValid is true, this property contains the subject identifier (user ID) associated with the token request. This value is typically extracted from the authorization code, refresh token, or user credentials provided in the token request, and represents the identity of the resource owner (user) for whom the access token will be issued. If IsValid is false, this property will be null.
    /// </summary>
    public string? SubjectId   { get; private init; }
    /// <summary>
    /// If IsValid is true, this property contains the list of scopes that were requested in the token request and successfully validated against the client's allowed scopes. This list will be used to determine what permissions the access token will have when issued. If IsValid is false, this property will be an empty list.
    /// </summary>
    public IReadOnlyList<string> Scopes { get; private init; } = [];
    /// <summary>
    /// If IsValid is true, this property contains the nonce value associated with the token request, if applicable. The nonce is typically included in the authorization code and can be used to mitigate replay attacks by ensuring that the same authorization code cannot be used multiple times. If IsValid is false or if the nonce is not applicable for the given grant type, this property will be null.
    /// </summary>
    public string? Nonce       { get; private init; }
    /// <summary>
    /// If IsValid is true and the token request is using the refresh token grant type, this property contains the RefreshToken entity that was validated based on the refresh_token provided in the request. This entity includes all relevant information about the refresh token (e.g., client ID, subject ID, scopes, expiration) that can be used in subsequent steps of the token issuance process. If IsValid is false or if the refresh token is not applicable for the given grant type, this property will be null.
    /// </summary>
    public RefreshToken? RefreshTokenEntity { get; private init; }

    /// <summary>
    /// True when the presented refresh token had ALREADY been rotated and was accepted only
    /// because it is inside the reuse grace period (snapshot taken at validation time).
    /// The token endpoint then issues new tokens without consuming it again.
    /// </summary>
    public bool IsRefreshTokenReuseWithinGracePeriod { get; private init; }

    /// <summary>
    /// When the user authenticated, if known (authorization code / refresh token grants).
    /// Emitted as the ID token <c>auth_time</c> claim.
    /// </summary>
    public DateTime? AuthTime { get; private init; }

    internal static TokenValidationResult SuccessRefresh(Client client, RefreshToken rt, bool reuseWithinGracePeriod)
        => new()
        {
            IsValid = true, Client = client, SubjectId = rt.SubjectId,
            Scopes = rt.Scopes.ToList().AsReadOnly(), RefreshTokenEntity = rt,
            IsRefreshTokenReuseWithinGracePeriod = reuseWithinGracePeriod,
            AuthTime = rt.AuthTime,
        };

    internal static TokenValidationResult SuccessCode(Client client, AuthorizationCode code)
        => new()
        {
            IsValid = true, Client = client, SubjectId = code.SubjectId,
            Scopes = code.Scopes.ToList().AsReadOnly(), Nonce = code.Nonce, AuthTime = code.AuthTime,
        };

    /// <summary>
    /// Creates a successful TokenValidationResult with the provided client, subject ID, scopes, nonce and refresh token entity. This method is used when the token request has been successfully validated and contains all the necessary information to proceed with issuing tokens or performing other actions as needed. The IsValid property will be set to true, and the Client, SubjectId, Scopes, Nonce and RefreshTokenEntity properties will be populated with the relevant information extracted from the token request.
    /// </summary>
    /// <param name="client"></param>
    /// <param name="subjectId"></param>
    /// <param name="scopes"></param>
    /// <param name="nonce"></param>
    /// <param name="rt"></param>
    /// <returns></returns>
    public static TokenValidationResult Success(Client client, string subjectId, IReadOnlyList<string> scopes, string? nonce = null, RefreshToken? rt = null)
        => new() { IsValid = true, Client = client, SubjectId = subjectId, Scopes = scopes, Nonce = nonce, RefreshTokenEntity = rt };
    /// <summary>
    /// Creates a failed TokenValidationResult with the provided error code and description. This method is used when the token request fails validation due to missing parameters, invalid credentials, unsupported grant types, or other issues. The IsValid property will be set to false, and the Error and ErrorDesc properties will be populated with the relevant information about the validation failure that can be returned to the client in the error response.
    /// </summary>
    /// <param name="error"></param>
    /// <param name="description"></param>
    /// <returns></returns>
    public static TokenValidationResult Fail(string error, string description)
        => new() { IsValid = false, Error = error, ErrorDesc = description };
}

/// <summary>
/// Validates token endpoint requests for all supported grant types:
/// authorization_code, client_credentials, refresh_token, password,
/// and the social token-exchange grants (google_id_token, facebook_access_token).
/// </summary>
public class TokenRequestValidator
{
    private readonly IClientStore                          _clients;
    private readonly IAuthorizationCodeStore               _codes;
    private readonly IRefreshTokenStore                    _refreshTokens;
    private readonly IUserAuthenticationService            _users;
    private readonly IReadOnlyList<IExternalTokenValidator> _externalValidators;

    private readonly TimeSpan _refreshTokenReuseGracePeriod;
    private readonly bool     _rotateRefreshTokens;
    private readonly ILogger? _logger;
    private readonly IReferenceTokenStore? _referenceTokens;
    private readonly bool _validateStamp;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRequestValidator"/> class.
    /// </summary>
    public TokenRequestValidator(
        IClientStore clients,
        IAuthorizationCodeStore codes,
        IRefreshTokenStore refreshTokens,
        IUserAuthenticationService users,
        IEnumerable<IExternalTokenValidator> externalValidators,
        IOptions<PulseAuthOptions>? options = null,
        ILogger<TokenRequestValidator>? logger = null,
        IReferenceTokenStore? referenceTokens = null)
    {
        _logger          = logger;
        _referenceTokens = referenceTokens;
        _validateStamp   = options?.Value.ValidateSecurityStampOnRefresh ?? true;
        _clients            = clients;
        _codes              = codes;
        _refreshTokens      = refreshTokens;
        _users              = users;
        _externalValidators = externalValidators.ToList().AsReadOnly();

        var opts = options?.Value;
        _rotateRefreshTokens = opts?.RotateRefreshTokens ?? true;
        _refreshTokenReuseGracePeriod = opts is { RotateRefreshTokens: true }
            ? opts.RefreshTokenReuseGracePeriod
            : TimeSpan.Zero;
    }

    /// <summary>
    /// Validates the token request parameters based on the specified grant type.
    /// Handles authorization_code, client_credentials, refresh_token, password,
    /// and any registered social token-exchange grant types.
    /// </summary>
    public async Task<TokenValidationResult> ValidateAsync(
        string? grantType,
        string? clientId,
        string? clientSecret,
        string? code,
        string? codeVerifier,
        string? redirectUri,
        string? scope,
        string? refreshToken,
        string? username,
        string? password,
        string? externalToken,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(grantType))
            return TokenValidationResult.Fail(OAuthErrors.InvalidRequest, "grant_type is required");

        if (string.IsNullOrWhiteSpace(clientId))
            return TokenValidationResult.Fail(OAuthErrors.InvalidClient, "client_id is required");

        var client = await _clients.FindClientByIdAsync(clientId, ct);
        if (client is null || !client.Enabled)
            return TokenValidationResult.Fail(OAuthErrors.InvalidClient, "Unknown or disabled client");

        // Authenticate confidential client
        if (!string.IsNullOrEmpty(client.ClientSecretHash))
        {
            if (string.IsNullOrEmpty(clientSecret) ||
                !Helpers.ClientSecretHelper.Verify(clientSecret, client.ClientSecretHash))
                return TokenValidationResult.Fail(OAuthErrors.InvalidClient, "Invalid client credentials");
        }

        if (!client.AllowedGrantTypes.Contains(grantType))
            return TokenValidationResult.Fail(OAuthErrors.UnsupportedGrantType, $"Grant type '{grantType}' is not allowed for this client");

        // client_credentials authenticates the CLIENT itself: a public client (no secret) would let
        // anyone who knows the client_id mint tokens. Require a confidential client (RFC 6749 §4.4).
        if (grantType == GrantTypes.ClientCredentials && string.IsNullOrEmpty(client.ClientSecretHash))
            return TokenValidationResult.Fail(OAuthErrors.UnauthorizedClient,
                "client_credentials requires a confidential client (configure ClientSecretHash)");

        // Check registered social / external token-exchange validators first
        var externalValidator = _externalValidators.FirstOrDefault(v => v.SupportedGrantType == grantType);
        if (externalValidator is not null)
            return await ValidateSocialTokenAsync(client, externalValidator, externalToken, scope, ct);

        return grantType switch
        {
            GrantTypes.AuthorizationCode  => await ValidateAuthCodeAsync(client, code, codeVerifier, redirectUri, ct),
            GrantTypes.ClientCredentials  => await ValidateClientCredentialsAsync(client, scope, ct),
            GrantTypes.RefreshToken       => await ValidateRefreshTokenAsync(client, refreshToken, ct),
            GrantTypes.Password           => await ValidatePasswordAsync(client, username, password, scope, ct),
            _                             => TokenValidationResult.Fail(OAuthErrors.UnsupportedGrantType, $"Unsupported grant_type: {grantType}")
        };
    }

    // ── Authorization Code ───────────────────────────────────────────────────

    private async Task<TokenValidationResult> ValidateAuthCodeAsync(
        Client client, string? code, string? codeVerifier, string? redirectUri, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(code))
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "code is required");

        var authCode = await _codes.FindByCodeAsync(code, ct);

        if (authCode is null)
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Authorization code not found");

        if (authCode.IsConsumed)
        {
            // Code replay: the code was intercepted or the client is misbehaving. Revoke the
            // tokens issued with it (RFC 6749 §4.1.2) before rejecting the request.
            await HandleCodeReuseAsync(_refreshTokens, authCode, client.ClientId, _logger, ct);
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Authorization code has already been used");
        }

        if (authCode.ExpiresAt < DateTime.UtcNow)
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Authorization code has expired");

        if (!string.Equals(authCode.ClientId, client.ClientId, StringComparison.Ordinal))
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Code was not issued to this client");

        if (!string.IsNullOrEmpty(authCode.RedirectUri) &&
            !string.Equals(authCode.RedirectUri, redirectUri, StringComparison.Ordinal))
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "redirect_uri mismatch");

        // PKCE validation
        if (!string.IsNullOrEmpty(authCode.CodeChallenge))
        {
            if (string.IsNullOrEmpty(codeVerifier))
                return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "code_verifier is required");

            if (!VerifyPkce(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod ?? "S256"))
                return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Invalid code_verifier");
        }

        return TokenValidationResult.SuccessCode(client, authCode);
    }

    // ── Client Credentials ───────────────────────────────────────────────────

    private Task<TokenValidationResult> ValidateClientCredentialsAsync(
        Client client, string? scope, CancellationToken ct)
    {
        var requestedScopes = (scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

        if (requestedScopes.Count == 0)
            requestedScopes = client.AllowedScopes.ToList();

        var invalidScopes = requestedScopes.Where(s => !client.AllowedScopes.Contains(s)).ToList();
        if (invalidScopes.Count > 0)
            return Task.FromResult(TokenValidationResult.Fail(OAuthErrors.InvalidScope, $"Scope(s) not allowed: {string.Join(", ", invalidScopes)}"));

        // No refresh tokens for client_credentials (RFC 6749 §4.4.3): the client can always
        // request a new access token with its own credentials.
        requestedScopes.Remove(StandardScopes.OfflineAccess);

        // client_id is both client and subject for client credentials
        return Task.FromResult(TokenValidationResult.Success(client, client.ClientId, requestedScopes.AsReadOnly()));
    }

    // ── Refresh Token ────────────────────────────────────────────────────────

    private async Task<TokenValidationResult> ValidateRefreshTokenAsync(
        Client client, string? refreshToken, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(refreshToken))
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "refresh_token is required");

        var rt = await _refreshTokens.FindByTokenAsync(refreshToken, ct);

        if (rt is null)
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Refresh token not found");

        // A rotated token is still accepted for a short grace period (concurrent tabs,
        // retries). The token endpoint then issues a new refresh token without consuming again.
        if (rt.IsConsumed && !rt.IsWithinReuseGracePeriod(_refreshTokenReuseGracePeriod, DateTime.UtcNow))
        {
            // Reuse of a rotated token outside the grace window: either the legitimate client
            // or an attacker holds a stolen copy. Revoke the whole family (RFC 9700 §4.14.2).
            if (_rotateRefreshTokens)
                await HandleRefreshTokenReuseAsync(_refreshTokens, rt, client.ClientId, _logger, ct);

            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Refresh token has already been used");
        }

        if (rt.ExpiresAt < DateTime.UtcNow)
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Refresh token has expired");

        if (!string.Equals(rt.ClientId, client.ClientId, StringComparison.Ordinal))
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Refresh token was not issued to this client");

        // The client may have lost offline access since the token was issued.
        if (!client.AllowOfflineAccess)
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Client is no longer allowed to use refresh tokens");

        // Deleted, disabled or locked-out users must not keep refreshing until the token expires.
        if (!await _users.IsActiveAsync(rt.SubjectId, ct))
        {
            await RevokeUserTokensAsync(rt, ct);
            _logger?.LogInformation(
                "Refresh rejected: user {SubjectId} is no longer active; revoked their tokens for client {ClientId}.",
                rt.SubjectId, rt.ClientId);
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "User is no longer active");
        }

        // Password change, "sign out everywhere", 2FA reset... change the security stamp: every
        // refresh token issued before that must stop working.
        if (_validateStamp && rt.UserStamp is not null)
        {
            var currentStamp = await _users.GetSecurityStampAsync(rt.SubjectId, ct);
            if (currentStamp is null ||
                !string.Equals(RefreshToken.ComputeTokenId(currentStamp), rt.UserStamp, StringComparison.Ordinal))
            {
                await RevokeUserTokensAsync(rt, ct);
                _logger?.LogInformation(
                    "Refresh rejected: security stamp of user {SubjectId} changed; revoked their tokens for client {ClientId}.",
                    rt.SubjectId, rt.ClientId);
                return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "The user's credentials have changed; sign in again");
            }
        }

        return TokenValidationResult.SuccessRefresh(client, rt, reuseWithinGracePeriod: rt.IsConsumed);
    }

    private async Task RevokeUserTokensAsync(RefreshToken rt, CancellationToken ct)
    {
        await _refreshTokens.RevokeBySubjectAsync(rt.SubjectId, rt.ClientId, ct);
        if (_referenceTokens is not null)
            await _referenceTokens.RemoveBySubjectAsync(rt.SubjectId, rt.ClientId, ct);
    }

    /// <summary>
    /// Revokes the rotation family of a reused refresh token and logs a security event.
    /// </summary>
    internal static async Task HandleRefreshTokenReuseAsync(
        IRefreshTokenStore store,
        RefreshToken reusedToken,
        string presentingClientId,
        ILogger? logger,
        CancellationToken ct)
    {
        var revoked = await store.RevokeFamilyAsync(reusedToken, ct);

        logger?.LogWarning(
            "Refresh token reuse detected (subject {SubjectId}, client {ClientId}, presented by client {PresentingClientId}). " +
            "Revoked {RevokedCount} token(s) of the rotation family; the user must sign in again.",
            reusedToken.SubjectId, reusedToken.ClientId, presentingClientId,
            revoked >= 0 ? revoked.ToString() : "all (subject + client)");
    }

    /// <summary>
    /// Revokes the refresh tokens issued from a replayed authorization code. The first refresh token
    /// of a code exchange is linked to the code (<see cref="RefreshToken.PreviousTokenId"/> = hash of
    /// the code), so the whole rotation family hanging from it is revoked.
    /// </summary>
    internal static async Task HandleCodeReuseAsync(
        IRefreshTokenStore store,
        AuthorizationCode code,
        string presentingClientId,
        ILogger? logger,
        CancellationToken ct)
    {
        var revoked = await store.RevokeFamilyAsync(new RefreshToken
        {
            Token     = code.Code,
            ClientId  = code.ClientId,
            SubjectId = code.SubjectId,
        }, ct);

        logger?.LogWarning(
            "Authorization code reuse detected (subject {SubjectId}, client {ClientId}, presented by client {PresentingClientId}). " +
            "Revoked {RevokedCount} refresh token(s) issued with it.",
            code.SubjectId, code.ClientId, presentingClientId,
            revoked >= 0 ? revoked.ToString() : "all (subject + client)");
    }

    // ── Resource Owner Password (legacy) ─────────────────────────────────────

    private async Task<TokenValidationResult> ValidatePasswordAsync(
        Client client, string? username, string? password, string? scope, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "username and password are required");

        var user = await _users.ValidateCredentialsAsync(username, password, ct);
        if (user is null)
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Invalid credentials");

        var requestedScopes = (scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                           .Where(s => client.AllowedScopes.Contains(s))
                                           .ToList();
        ApplyOfflineAccessPolicy(client, requestedScopes);

        return TokenValidationResult.Success(client, user.SubjectId, requestedScopes.AsReadOnly());
    }

    // ── Social Token Exchange ────────────────────────────────────────────────

    private async Task<TokenValidationResult> ValidateSocialTokenAsync(
        Client client,
        IExternalTokenValidator validator,
        string? externalToken,
        string? scope,
        CancellationToken ct)
    {
        if (string.IsNullOrEmpty(externalToken))
            return TokenValidationResult.Fail(OAuthErrors.InvalidRequest, "token is required for social grant types");

        var identity = await validator.ValidateAsync(externalToken, ct);
        if (identity is null)
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, $"Invalid or expired {validator.ProviderName} token");

        // Find existing user linked to this external provider, or auto-provision a new one
        var user = await _users.FindByExternalProviderAsync(validator.ProviderName, identity.SubjectId, ct);
        if (user is null)
        {
            var claims = BuildExternalClaims(identity);
            try
            {
                user = await _users.AutoProvisionUserAsync(validator.ProviderName, identity.SubjectId, claims, ct);
            }
            catch (Exceptions.UserProvisioningException ex)
            {
                _logger?.LogWarning(ex, "Auto-provisioning of a {Provider} user failed ({Reason})", validator.ProviderName, ex.Reason);
                return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, ex.Message);
            }
        }

        var requestedScopes = (scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                           .Where(s => client.AllowedScopes.Contains(s))
                                           .ToList();

        if (requestedScopes.Count == 0)
            requestedScopes = client.AllowedScopes
                                    .Where(s => s != StandardScopes.OfflineAccess)
                                    .ToList();
        ApplyOfflineAccessPolicy(client, requestedScopes);

        return TokenValidationResult.Success(client, user.SubjectId, requestedScopes.AsReadOnly());
    }

    /// <summary>
    /// offline_access (= a refresh token) is only granted to clients with
    /// <see cref="Client.AllowOfflineAccess"/>, consistently with the authorize endpoint.
    /// </summary>
    private static void ApplyOfflineAccessPolicy(Client client, List<string> scopes)
    {
        if (!client.AllowOfflineAccess)
            scopes.Remove(StandardScopes.OfflineAccess);
    }

    private static IEnumerable<Claim> BuildExternalClaims(ExternalIdentity identity)
    {
        var claims = new List<Claim>();
        if (!string.IsNullOrEmpty(identity.Email))
            claims.Add(new(ClaimTypes.Email,    identity.Email));
        if (!string.IsNullOrEmpty(identity.Name))
            claims.Add(new(ClaimTypes.Name,     identity.Name));
        if (!string.IsNullOrEmpty(identity.GivenName))
            claims.Add(new(ClaimTypes.GivenName, identity.GivenName));
        if (!string.IsNullOrEmpty(identity.FamilyName))
            claims.Add(new(ClaimTypes.Surname,  identity.FamilyName));
        if (!string.IsNullOrEmpty(identity.Picture))
            claims.Add(new("picture",           identity.Picture));
        return claims;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static bool VerifyPkce(string verifier, string challenge, string method)
    {
        if (method == "plain")
            return CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(verifier),
                Encoding.ASCII.GetBytes(challenge));

        // S256: BASE64URL(SHA256(ASCII(verifier)))
        var hash       = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var computed   = Base64UrlEncode(hash);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(computed),
            Encoding.ASCII.GetBytes(challenge));
    }

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
}
