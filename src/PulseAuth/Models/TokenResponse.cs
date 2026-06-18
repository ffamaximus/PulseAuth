using System.Text.Json.Serialization;

namespace PulseAuth.Models;

/// <summary>
/// OAuth2 token endpoint response. Serializes to the standard JSON format.
/// </summary>
public class TokenResponse
{
    /// <summary>
    /// The access token issued by the authorization server. This token is used to access protected resources and must be included in the Authorization header of API requests, e.g. "Authorization
    /// </summary>
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = default!;

    /// <summary>
    /// The type of the token issued. The value is typically "Bearer", which indicates that the access token is a bearer token. Clients must use this value to determine how to use the access token when making API requests.
    /// </summary>
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// The lifetime in seconds of the access token. After this time, the access token expires and cannot be used to access protected resources. Clients should use this value to determine when to refresh the access token using a refresh token (if available) or prompt the user to re-authenticate.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    /// <summary>
    /// The refresh token, which can be used to obtain new access tokens using the Refresh Token flow. This token is typically long-lived and should be stored securely by the client. The presence of this field indicates that the authorization server supports issuing refresh tokens for the given grant type and client configuration.
    /// </summary>
    [JsonPropertyName("refresh_token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RefreshToken { get; set; }

    /// <summary>
    /// The ID token, which is a JWT that contains claims about the authenticated user. This token is typically issued in OpenID Connect flows (e.g., Authorization Code flow with "openid" scope) and can be used by the client to obtain user information without making an additional request to the userinfo endpoint. The presence of this field indicates that the authorization server supports issuing ID tokens for the given grant type and client configuration.
    /// </summary>
    [JsonPropertyName("id_token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdToken { get; set; }

    /// <summary>
    /// The scope of the access token, which is a space-separated list of scopes that the access token is valid for. This field is included in the response if the scope of the issued access token is different from the scope requested by the client. Clients should use this value to determine what permissions the access token has when making API requests.
    /// </summary>
    [JsonPropertyName("scope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Scope { get; set; }
}
