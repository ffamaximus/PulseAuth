using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Constants;
using PulseAuth.Models;

namespace PulseAuth.Validators;

/// <summary>Result of an authorization request validation.</summary>
public class AuthorizeValidationResult
{
    /// <summary>
    /// Indicates whether the authorization request is valid. If false, the Error and ErrorDesc properties will contain details about the validation failure, which should be returned to the client in the error response. If true, the Client and RequestedScopes properties will contain the validated client information and scopes that can be used to proceed with the authorization process.
    /// </summary>
    public bool IsValid { get; private init; }
    /// <summary>
    /// If IsValid is false, this property contains the OAuth2 error code that describes the reason for the validation failure. The value should be one of the standard error codes defined in RFC 6749 (e.g., "invalid_request", "unauthorized_client", "unsupported_response_type", "invalid_scope") or a custom error code if needed. This value will be included in the error response sent back to the client.
    /// </summary>
    public string? Error { get; private init; }
    /// <summary>
    /// If IsValid is false, this property contains a human-readable description of the error that occurred during validation. This description can provide additional context or details about the error to help the client understand what went wrong. This value will be included in the error response sent back to the client, typically in the "error_description" field of the JSON response body.
    /// </summary>
    public string? ErrorDesc { get; private init; }
    /// <summary>
    /// If IsValid is true, this property contains the Client object that was successfully validated based on the client_id provided in the authorization request. This object includes all relevant information about the client (e.g., allowed grant types, redirect URIs, allowed scopes) that can be used in subsequent steps of the authorization process. If IsValid is false, this property will be null.
    /// </summary>
    public Client? Client { get; private init; }
    /// <summary>
    /// If IsValid is true, this property contains the list of scopes that were requested in the authorization request and successfully validated against the client's allowed scopes. This list will be used to determine what permissions the access token will have if the authorization process is successful. If IsValid is false, this property will be an empty list. Note that the "offline_access" scope is handled separately and may not be included in this list even if it was requested, depending on the client's configuration.
    /// </summary>
    public IReadOnlyList<string> RequestedScopes { get; private init; } = [];
    /// <summary>
    /// The redirect URI that has been verified against the client's registration
    /// (exact match, or the single registered URI when the request omitted it).
    /// It is <c>null</c> when the client or the redirect URI could not be validated —
    /// in that case the error MUST be shown to the user and NEVER redirected
    /// (RFC 6749 §4.1.2.1), otherwise the endpoint becomes an open redirector.
    /// </summary>
    public string? ValidatedRedirectUri { get; private init; }

    /// <summary>
    /// Creates a successful AuthorizeValidationResult with the validated client and requested scopes. This method should be used when the authorization request parameters have been successfully validated and the authorization process can proceed. The client parameter should contain the Client object that was validated, and the scopes parameter should contain the list of scopes that were requested and allowed for this client. The resulting AuthorizeValidationResult will have IsValid set to true, and the Error and ErrorDesc properties will be null.
    /// </summary>
    /// <param name="client"></param>
    /// <param name="scopes"></param>
    /// <param name="validatedRedirectUri">The redirect URI verified against the client's registration.</param>
    /// <returns></returns>
    public static AuthorizeValidationResult Success(Client client, IReadOnlyList<string> scopes, string? validatedRedirectUri = null)
        => new() { IsValid = true, Client = client, RequestedScopes = scopes, ValidatedRedirectUri = validatedRedirectUri };

    /// <summary>
    /// Creates a failed AuthorizeValidationResult with the specified error code and description. This method should be used when the authorization request parameters fail validation for any reason (e.g., missing client_id, invalid redirect_uri, unsupported response_type). The error parameter should contain the appropriate OAuth2 error code that describes the reason for the failure, and the description parameter should provide a human-readable explanation of the error. The resulting AuthorizeValidationResult will have IsValid set to false, and the Client and RequestedScopes properties will be null or empty.
    /// </summary>
    /// <param name="error"></param>
    /// <param name="description"></param>
    /// <returns></returns>
    public static AuthorizeValidationResult Fail(string error, string description)
        => new() { IsValid = false, Error = error, ErrorDesc = description };

    /// <summary>
    /// Creates a failed result that can be safely reported to the client by redirecting
    /// to <paramref name="validatedRedirectUri"/> (only use with an already-validated URI).
    /// </summary>
    public static AuthorizeValidationResult Fail(string error, string description, string validatedRedirectUri)
        => new() { IsValid = false, Error = error, ErrorDesc = description, ValidatedRedirectUri = validatedRedirectUri };
}

/// <summary>
/// Validates parameters sent to the authorize endpoint.
/// </summary>
public class AuthorizeRequestValidator
{
    private readonly IClientStore _clients;
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizeRequestValidator"/> class with the specified client store. The client store is used to retrieve client information based on the client_id provided in the authorization request, which is essential for validating the request parameters (e.g., allowed grant types, redirect URIs, allowed scopes). This validator will check for the presence and validity of required parameters, ensure that the client is authorized to use the requested response type and scopes, and return a validation result that indicates whether the request is valid or not, along with any relevant error information if it is invalid.
    /// </summary>
    /// <param name="clients"></param>
    /// <param name="options">PulseAuth options (PKCE policy).</param>
    public AuthorizeRequestValidator(IClientStore clients, IOptions<PulseAuthOptions>? options = null)
    {
        _clients        = clients;
        _allowPlainPkce = options?.Value.AllowPlainPkce ?? false;
        _ignoreUnknownScopes = options?.Value.IgnoreUnknownScopes ?? false;
        _supportedScopes     = options?.Value.SupportedScopes.ToHashSet(StringComparer.Ordinal) ?? [];
    }

    private readonly bool _allowPlainPkce;
    private readonly bool _ignoreUnknownScopes;
    private readonly HashSet<string> _supportedScopes;

    /// <summary>
    /// Validates the parameters of an authorization request. This method checks for the presence and validity of required parameters such as client_id, response_type, redirect_uri, scope, code_challenge, and code_challenge_method. It retrieves the client information from the client store based on the provided client_id and validates that the client is enabled and authorized to use the requested response type and scopes. It also validates the redirect_uri against the client's registered redirect URIs and checks PKCE requirements if applicable. The method returns an AuthorizeValidationResult indicating whether the validation was successful or if there were any errors that should be communicated back to the client.
    /// </summary>
    /// <param name="clientId"></param>
    /// <param name="responseType"></param>
    /// <param name="redirectUri"></param>
    /// <param name="scope"></param>
    /// <param name="codeChallenge"></param>
    /// <param name="codeChallengeMethod"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public async Task<AuthorizeValidationResult> ValidateAsync(
        string? clientId,
        string? responseType,
        string? redirectUri,
        string? scope,
        string? codeChallenge,
        string? codeChallengeMethod,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            return AuthorizeValidationResult.Fail(OAuthErrors.InvalidRequest, "client_id is required");

        var client = await _clients.FindClientByIdAsync(clientId, ct);
        if (client is null || !client.Enabled)
            return AuthorizeValidationResult.Fail(OAuthErrors.UnauthorizedClient, "Unknown or disabled client");

        // Validate redirect_uri FIRST. Until it is validated, every error must be
        // rendered locally (no redirect) — RFC 6749 §4.1.2.1.
        if (!string.IsNullOrEmpty(redirectUri))
        {
            if (!client.RedirectUris.Any(u => string.Equals(u, redirectUri, StringComparison.Ordinal)))
                return AuthorizeValidationResult.Fail(OAuthErrors.InvalidRequest, "Invalid redirect_uri");
        }
        else if (client.RedirectUris.Count == 1 && !IsOpenIdRequest(scope))
        {
            // Plain OAuth2 allows omitting redirect_uri when exactly one is registered
            // (RFC 6749 §3.1.2.3). OpenID Connect requests MUST always send it (OIDC Core §3.1.2.1).
            redirectUri = client.RedirectUris.First();
        }
        else
        {
            return AuthorizeValidationResult.Fail(OAuthErrors.InvalidRequest, "redirect_uri is required");
        }

        // From here on the redirect_uri is trusted, so errors are returned to the client.
        var validatedRedirectUri = redirectUri;

        // Validate response_type
        if (string.IsNullOrEmpty(responseType))
            return AuthorizeValidationResult.Fail(OAuthErrors.InvalidRequest, "response_type is required", validatedRedirectUri);

        if (responseType != "code")
            return AuthorizeValidationResult.Fail(OAuthErrors.UnsupportedResponseType, "Only 'code' response type is supported", validatedRedirectUri);

        if (!client.AllowedGrantTypes.Contains(GrantTypes.AuthorizationCode))
            return AuthorizeValidationResult.Fail(OAuthErrors.UnauthorizedClient, "Client is not allowed to use authorization_code grant", validatedRedirectUri);

        // Validate PKCE
        if (client.RequirePkce && string.IsNullOrEmpty(codeChallenge))
            return AuthorizeValidationResult.Fail(OAuthErrors.InvalidRequest, "code_challenge is required for this client", validatedRedirectUri);

        if (!string.IsNullOrEmpty(codeChallengeMethod) &&
            codeChallengeMethod != "S256" && !(codeChallengeMethod == "plain" && _allowPlainPkce))
            return AuthorizeValidationResult.Fail(OAuthErrors.InvalidRequest,
                _allowPlainPkce ? "Unsupported code_challenge_method. Use S256 or plain"
                                : "Unsupported code_challenge_method. Use S256",
                validatedRedirectUri);

        // Validate scopes
        var requestedScopes = (scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        if (requestedScopes.Count == 0)
            requestedScopes = [StandardScopes.OpenId];

        if (_ignoreUnknownScopes)
            requestedScopes.RemoveAll(s => !_supportedScopes.Contains(s) && !client.AllowedScopes.Contains(s) &&
                                           s != StandardScopes.OfflineAccess);

        var invalidScopes = requestedScopes
            .Except([StandardScopes.OfflineAccess]) // handled separately
            .Where(s => !client.AllowedScopes.Contains(s))
            .ToList();

        if (invalidScopes.Count > 0)
            return AuthorizeValidationResult.Fail(OAuthErrors.InvalidScope, $"Scope(s) not allowed: {string.Join(", ", invalidScopes)}", validatedRedirectUri);

        // offline_access only allowed when client supports it
        if (requestedScopes.Contains(StandardScopes.OfflineAccess) && !client.AllowOfflineAccess)
            requestedScopes.Remove(StandardScopes.OfflineAccess);

        return AuthorizeValidationResult.Success(client, requestedScopes.AsReadOnly(), validatedRedirectUri);
    }

    private static bool IsOpenIdRequest(string? scope)
        => !string.IsNullOrEmpty(scope) &&
           scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains(StandardScopes.OpenId);
}
