namespace PulseAuth.Constants;

/// <summary>Standard OAuth2 / OpenID Connect error codes.</summary>
public static class OAuthErrors
{
    /// <summary>
    /// Authorization endpoint errors as defined in RFC 6749 Section
    /// </summary>
    public const string InvalidRequest          = "invalid_request";

    /// <summary>
    /// The client is not authorized to request an authorization code using this method.
    /// </summary>
    public const string UnauthorizedClient      = "unauthorized_client";

    /// <summary>
    /// The resource owner or authorization server denied the request.
    /// </summary>
    public const string AccessDenied            = "access_denied";

    /// <summary>
    /// The authorization server does not support obtaining an authorization code using this method.
    /// </summary>
    public const string UnsupportedResponseType = "unsupported_response_type";

    /// <summary>
    /// The requested scope is invalid, unknown, or malformed.
    /// </summary>
    public const string InvalidScope            = "invalid_scope";

    /// <summary>
    /// The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
    /// </summary>
    public const string ServerError             = "server_error";

    /// <summary>
    /// The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.
    /// </summary>
    public const string TemporarilyUnavailable  = "temporarily_unavailable";

    // Token endpoint errors
    /// <summary>
    /// The client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).
    /// </summary>
    public const string InvalidClient     = "invalid_client";

    /// <summary>
    /// The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.
    /// </summary>
    public const string InvalidGrant      = "invalid_grant";

    /// <summary>
    /// The authenticated client is not authorized to use this authorization grant type.
    /// </summary>
    public const string UnsupportedGrantType = "unsupported_grant_type";

    // Resource errors
    /// <summary>
    /// The request requires higher privileges than provided by the access token.
    /// </summary>
    public const string InsufficientScope = "insufficient_scope";

    /// <summary>
    /// The access token provided is expired, revoked, malformed, or invalid for other reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized) status code. The client MAY request a new access token and retry the protected resource request.
    /// </summary>
    public const string InvalidToken      = "invalid_token";
}
