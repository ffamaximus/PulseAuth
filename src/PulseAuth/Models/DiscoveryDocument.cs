using System.Text.Json.Serialization;

namespace PulseAuth.Models;

/// <summary>
/// OpenID Connect discovery document served at /.well-known/openid-configuration.
/// </summary>
public class DiscoveryDocument
{
    /// <summary>
    /// The issuer (iss) claim value in JWTs.
    /// </summary>
    [JsonPropertyName("issuer")]
    public string Issuer { get; set; } = default!;
    /// <summary>
    /// The URL of the authorization endpoint where clients redirect users to authenticate and authorize.
    /// </summary>

    [JsonPropertyName("authorization_endpoint")]
    public string AuthorizationEndpoint { get; set; } = default!;
    /// <summary>
    /// The URL of the token endpoint where clients exchange authorization codes or refresh tokens for access tokens.
    /// </summary>

    [JsonPropertyName("token_endpoint")]
    public string TokenEndpoint { get; set; } = default!;

    /// <summary>
    /// The URL of the userinfo endpoint where clients can retrieve user profile information using an access token.
    /// </summary>
    [JsonPropertyName("userinfo_endpoint")]
    public string UserInfoEndpoint { get; set; } = default!;

    /// <summary>
    /// The URL of the JSON Web Key Set (JWKS) endpoint where clients can retrieve the public keys used to verify JWT signatures.
    /// </summary>
    [JsonPropertyName("jwks_uri")]
    public string JwksUri { get; set; } = default!;

    /// <summary>
    /// The URL of the end session endpoint where clients can redirect users to log out of their session.
    /// </summary>
    [JsonPropertyName("end_session_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EndSessionEndpoint { get; set; }

    /// <summary>
    /// The URL of the revocation endpoint where clients can revoke access tokens or refresh tokens.
    /// </summary>
    [JsonPropertyName("revocation_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RevocationEndpoint { get; set; }

    /// <summary>Token introspection endpoint (RFC 7662).</summary>
    [JsonPropertyName("introspection_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IntrospectionEndpoint { get; set; }

    /// <summary>Supported values of the prompt parameter.</summary>
    [JsonPropertyName("prompt_values_supported")]
    public IEnumerable<string> PromptValuesSupported { get; set; } = ["none", "login", "consent"];

    /// <summary>
    /// Response types supported by the authorization server. The default is "code", which means the Authorization Code flow is supported. If you want to support the Implicit flow (not recommended for new applications), you can include "id_token" and/or "token id_token" in this list and implement the necessary logic in your authorization endpoint to handle those response types.
    /// </summary>
    [JsonPropertyName("response_types_supported")]
    public IEnumerable<string> ResponseTypesSupported { get; set; } = ["code"];

    /// <summary>
    /// Subject identifier types supported by the authorization server. The default is "public", which means the same subject ID is used for a user across all clients. If you want to support pairwise subject identifiers (different subject IDs for the same user depending on the client), you can include "pairwise" in this list and implement the necessary logic in your user authentication service to generate consistent pairwise IDs based on the client_id and user information.
    /// </summary>
    [JsonPropertyName("subject_types_supported")]
    public IEnumerable<string> SubjectTypesSupported { get; set; } = ["public"];

    /// <summary>
    /// Algorithms supported for signing ID tokens. The default is "RS256", which is the most common and secure choice. If you only support symmetric signing (e.g., "HS256"), make sure to configure your clients accordingly and ensure that the shared secret is kept secure.
    /// </summary>
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public IEnumerable<string> IdTokenSigningAlgValuesSupported { get; set; } = ["RS256"];

    /// <summary>
    /// Listed of scopes that the authorization server supports for use in the scope parameter of authorization requests.
    /// </summary>
    [JsonPropertyName("scopes_supported")]
    public IEnumerable<string> ScopesSupported { get; set; } = [];

    /// <summary>
    /// Listed of claims that the authorization server can include in ID tokens or userinfo responses.
    /// </summary>
    [JsonPropertyName("claims_supported")]
    public IEnumerable<string> ClaimsSupported { get; set; } = [];


    /// <summary>
    /// Listed of grant types that the authorization server supports for use in the grant_type parameter of token requests. The default includes "authorization_code", "client_credentials", and "refresh_token". If you want to support legacy flows like Resource Owner Password or Implicit, you can include "password" and/or "implicit" in this list and implement the necessary logic in your token endpoint to handle those grant types. However, these flows are deprecated in OAuth 2.1 and not recommended for new applications.
    /// </summary>
    [JsonPropertyName("grant_types_supported")]
    public IEnumerable<string> GrantTypesSupported { get; set; } = ["authorization_code", "client_credentials", "refresh_token"];

    /// <summary>
    /// Listed of client authentication methods that the authorization server supports for use in the token endpoint. The default includes "client_secret_basic" and "client_secret_post", which are the most common methods for confidential clients. If you want to support other methods (e.g., "client_secret_jwt", "private_key_jwt"), you can include them in this list and implement the necessary logic in your token endpoint to handle those authentication methods. For public clients (e.g., single-page applications), you can include "none" in this list and allow unauthenticated requests to the token endpoint, but make sure to implement additional security measures (e.g., PKCE) to mitigate the risks of public clients.
    /// </summary>
    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public IEnumerable<string> TokenEndpointAuthMethodsSupported { get; set; } = ["client_secret_basic", "client_secret_post"];

    /// <summary>
    /// Listed of PKCE code challenge methods that the authorization server supports for use in the code_challenge_method parameter of authorization requests. The default includes "S256" (SHA-256) and "plain" (no hashing). "S256" is the recommended method for security reasons, while "plain" is provided for compatibility with clients that do not support hashing. If you want to enforce the use of PKCE for all clients, you can include only "S256" in this list and reject authorization requests that do not include a valid code_challenge and code_challenge_method.
    /// </summary>
    [JsonPropertyName("code_challenge_methods_supported")]
    public IEnumerable<string> CodeChallengeMethodsSupported { get; set; } = ["S256", "plain"];
}
