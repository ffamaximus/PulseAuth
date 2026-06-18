using System.Security.Cryptography;
using System.Text;
using PulseAuth.Abstractions;
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
/// Validates token endpoint requests (authorization_code, client_credentials, refresh_token).
/// </summary>
public class TokenRequestValidator
{
    private readonly IClientStore               _clients;
    private readonly IAuthorizationCodeStore    _codes;
    private readonly IRefreshTokenStore         _refreshTokens;
    private readonly IUserAuthenticationService _users;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRequestValidator"/> class with the specified client store, authorization code store, refresh token store, and user authentication service. These dependencies are used to validate the various parameters of the token request based on the grant type (e.g., validating client credentials, checking authorization codes, verifying refresh tokens, and authenticating user credentials). The validator will use these services to ensure that the token request is valid and contains all necessary information before proceeding with token issuance or returning an error response to the client.
    /// </summary>
    /// <param name="clients"></param>
    /// <param name="codes"></param>
    /// <param name="refreshTokens"></param>
    /// <param name="users"></param>
    public TokenRequestValidator(
        IClientStore clients,
        IAuthorizationCodeStore codes,
        IRefreshTokenStore refreshTokens,
        IUserAuthenticationService users)
    {
        _clients       = clients;
        _codes         = codes;
        _refreshTokens = refreshTokens;
        _users         = users;
    }

    /// <summary>
    /// Validates the token request parameters based on the specified grant type and other relevant information. This method checks for the presence of required parameters, validates client credentials, verifies authorization codes and refresh tokens, and authenticates user credentials as needed based on the grant type. The result of the validation is returned as a TokenValidationResult object, which indicates whether the request is valid and contains any relevant information or errors that should be returned to the client. The validation logic is implemented according to the OAuth2 specification and best practices for secure token issuance.
    /// </summary>
    /// <param name="grantType"></param>
    /// <param name="clientId"></param>
    /// <param name="clientSecret"></param>
    /// <param name="code"></param>
    /// <param name="codeVerifier"></param>
    /// <param name="redirectUri"></param>
    /// <param name="scope"></param>
    /// <param name="refreshToken"></param>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
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
                !VerifySecret(clientSecret, client.ClientSecretHash))
                return TokenValidationResult.Fail(OAuthErrors.InvalidClient, "Invalid client credentials");
        }

        if (!client.AllowedGrantTypes.Contains(grantType))
            return TokenValidationResult.Fail(OAuthErrors.UnsupportedGrantType, $"Grant type '{grantType}' is not allowed for this client");

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
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Authorization code has already been used");

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

        return TokenValidationResult.Success(
            client,
            authCode.SubjectId,
            authCode.Scopes.ToList().AsReadOnly(),
            authCode.Nonce);
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

        if (rt.IsConsumed)
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Refresh token has already been used");

        if (rt.ExpiresAt < DateTime.UtcNow)
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Refresh token has expired");

        if (!string.Equals(rt.ClientId, client.ClientId, StringComparison.Ordinal))
            return TokenValidationResult.Fail(OAuthErrors.InvalidGrant, "Refresh token was not issued to this client");

        return TokenValidationResult.Success(client, rt.SubjectId, rt.Scopes.ToList().AsReadOnly(), rt: rt);
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

        return TokenValidationResult.Success(client, user.SubjectId, requestedScopes.AsReadOnly());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static bool VerifySecret(string secret, string storedHash)
    {
        // Constant-time comparison of SHA256 hashes
        var hash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(secret))).ToLowerInvariant();
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(hash),
            Encoding.UTF8.GetBytes(storedHash.ToLowerInvariant()));
    }

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
