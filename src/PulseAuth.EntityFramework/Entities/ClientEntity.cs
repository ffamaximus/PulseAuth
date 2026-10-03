using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PulseAuth.EntityFramework.Entities;

/// <summary>
/// Represents an OAuth2/OpenID Connect client application. This entity contains all the necessary information about a client, such as its allowed grant types, redirect URIs, allowed scopes, and other configuration settings. The ClientEntity is used by the authorization server to validate incoming requests and determine how to handle them based on the client's configuration. Each client has a unique ClientId that is used to identify it during the authorization process. The ClientSecretHash is used for confidential clients that require authentication, while public clients can have this field set to null. The navigation properties allow for easy access to related entities such as grant types, redirect URIs, scopes, CORS origins and claims associated with the client. This design allows for flexible and extensible client configurations to support various types of applications (e.g., web apps, mobile apps, SPAs) and authorization scenarios (e.g., authorization code flow, implicit flow, client credentials flow).
/// </summary>
[Table("PulseAuth_Clients")]
public class ClientEntity
{
    /// <summary>
    /// The unique identifier for the client application. This value is used by the authorization server to identify the client during the authorization process. It must be unique across all clients and is typically a string that can be easily remembered by developers (e.g., "my-web-app", "mobile-client"). The ClientId is required and serves as the primary key for the ClientEntity in the database.
    /// </summary>
    [Key]
    [MaxLength(200)]
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// The hash of the client secret used for authentication of confidential clients. This field is required for confidential clients that need to authenticate with the authorization server (e.g., web applications, backend services) and should be null for public clients (e.g., single-page applications, mobile apps) that do not require authentication. The ClientSecretHash should be generated using a secure hashing algorithm (e.g., SHA256) and stored securely in the database. During the token request, the client will provide its client_id and client_secret, which will be hashed and compared against this stored hash to authenticate the client.
    /// </summary>
    [MaxLength(512)]
    public string? ClientSecretHash { get; set; }

    /// <summary>
    /// The display name of the client application. This is a human-readable name that can be used in user interfaces (e.g., consent screens) to identify the client to end-users. The ClientName is required and should be descriptive enough to help users understand which application is requesting access to their resources. It does not have to be unique across clients, but it should be meaningful and recognizable to users.
    /// </summary>
    [Required, MaxLength(200)]
    public string ClientName { get; set; } = default!;

    /// <summary>
    /// A brief description of the client application. This field is optional and can be used to provide additional information about the client, such as its purpose, features, or any other relevant details that may help users understand what the client does when they see it in a consent screen or other user interface. The Description can be up to 1000 characters long and should be concise and informative.
    /// </summary>
    [MaxLength(1000)]
    public string? Description { get; set; }

    /// <summary>
    /// The URL of the client's logo image. This field is optional and can be used to provide a visual representation of the client application in user interfaces (e.g., consent screens). The LogoUri should point to a valid image resource (e.g., PNG, JPEG) that can be displayed to users when they are asked to grant permissions to the client. The URL should be accessible and secure (e.g., using HTTPS) to ensure that it can be loaded properly in the user's browser. The LogoUri can be up to 500 characters long and should be a well-formed URL.
    /// </summary>
    [MaxLength(500)]
    public string? LogoUri { get; set; }

    /// <summary>
    /// Indicates whether the client is enabled and can be used for authorization. If false, the authorization server will reject all requests from this client and return an appropriate error response (e.g., "unauthorized_client"). This field allows administrators to disable a client without deleting its configuration from the database, which can be useful for temporarily suspending access or deactivating clients that are no longer in use. By default, this field is set to true, meaning that new clients are enabled when created.
    /// </summary>
    public bool Enabled { get; set; } = true;
    /// <summary>
    /// Indicates whether the client is a public client that does not require authentication (e.g., single-page applications, mobile apps). If true, the ClientSecretHash should be null, and the authorization server will allow unauthenticated requests from this client. If false, the client is considered a confidential client that must authenticate using its client secret. By default, this field is set to false, meaning that new clients are considered confidential unless explicitly marked as public.
    /// </summary>
    public bool RequirePkce { get; set; } = true;

    /// <summary>
    /// Indicates whether the client is allowed to request offline access, which means it can receive refresh tokens that allow it to obtain new access tokens without user interaction. If true, the client can include the "offline_access" scope in its authorization requests, and the authorization server will issue refresh tokens when appropriate. If false, the client cannot request offline access, and any attempts to include the "offline_access" scope will be ignored or rejected by the authorization server. By default, this field is set to false, meaning that new clients are not allowed to request offline access unless explicitly configured to do so.
    /// </summary>
    public bool AllowOfflineAccess { get; set; } = false;
    /// <summary>
    /// Indicates whether the client requires user consent for authorization. If true, the authorization server will display a consent screen to the user during the authorization process, asking them to grant permissions to the client for the requested scopes. If false, the authorization server will skip the consent screen and automatically grant permissions to the client based on its configuration. By default, this field is set to false, meaning that new clients do not require user consent unless explicitly configured to do so. This setting can be useful for trusted clients or internal applications where user consent is not necessary or desired.
    /// </summary>
    public bool RequireConsent { get; set; } = false;
    /// <summary>
    /// Indicates whether the client allows access tokens to be transmitted via the browser (e.g., in the URL fragment for implicit flow). If true, the authorization server will allow access tokens to be returned in the URL fragment during the authorization process, which can be useful for single-page applications that need to receive access tokens directly in the browser. If false, the authorization server will not allow access tokens to be returned in the URL fragment, and clients will need to use other flows (e.g., authorization code flow with PKCE) to obtain access tokens securely. By default, this field is set to false, meaning that new clients do not allow access tokens in the browser unless explicitly configured to do so.
    /// </summary>
    public int AccessTokenLifetime { get; set; } = 3600;
    /// <summary>
    /// The lifetime in seconds of the refresh token issued to the client. This value determines how long a refresh token is valid before it expires and can no longer be used to obtain new access tokens. The default value is 2592000 seconds (30 days), which means that refresh tokens will be valid for 30 days after they are issued. Clients should use this value to determine when to prompt users to re-authenticate or when to request new refresh tokens if needed. It is important to set an appropriate refresh token lifetime based on the security requirements of your application and the expected usage patterns of your clients.
    /// </summary>
    public int RefreshTokenLifetime { get; set; } = 2592000;
    /// <summary>
    /// The lifetime in seconds of the authorization code issued to the client. This value determines how long an authorization code is valid before it expires and can no longer be exchanged for an access token. The default value is 300 seconds (5 minutes), which means that authorization codes will be valid for 5 minutes after they are issued. Clients should use this value to determine how quickly they need to exchange the authorization code for an access token during the authorization process. Setting a short lifetime for authorization codes can help mitigate certain security risks (e.g., interception of authorization codes) while still allowing enough time for legitimate clients to complete the exchange process.
    /// </summary>
    public int AuthorizationCodeLifetime { get; set; } = 300;
    /// <summary>
    /// The lifetime in seconds of the ID token issued to the client. This value determines how long an ID token is valid before it expires and can no longer be used to obtain user information or authenticate the user. The default value is 300 seconds (5 minutes), which means that ID tokens will be valid for 5 minutes after they are issued. Clients should use this value to determine when to prompt users to re-authenticate or when to request new ID tokens if needed. Setting an appropriate lifetime for ID tokens is important for security reasons, as it helps limit the window of opportunity for attackers to misuse stolen ID tokens while still providing a reasonable user experience for legitimate clients.
    /// </summary>
    public int IdentityTokenLifetime { get; set; } = 300;

    /// <summary>Access token format: 0 = JWT (default), 1 = Reference (1.4.0+).</summary>
    public int AccessTokenType { get; set; } = 0;

    /// <summary>The client may introspect tokens issued to any client (1.4.0+).</summary>
    public bool AllowIntrospection { get; set; } = false;

    // Navigation
    /// <summary>
    /// The collection of grant types that the client is allowed to use. This collection contains instances of ClientGrantTypeEntity, which represent the individual grant types (e.g., "authorization_code", "client_credentials", "refresh_token") that the client can use when making authorization requests. The authorization server will check this collection to determine if a client is authorized to use a specific grant type during the token request process. Clients must have at least one allowed grant type to be able to obtain access tokens from the authorization server.
    /// </summary>
    public ICollection<ClientGrantTypeEntity> GrantTypes { get; set; } = [];
    /// <summary>
    /// The collection of redirect URIs registered for the client. This collection contains instances of ClientRedirectUriEntity, which represent the individual redirect URIs that the client can use during the authorization process. The authorization server will check this collection to validate the redirect_uri parameter provided in authorization requests and ensure that it matches one of the registered URIs for the client. Redirect URIs are essential for security reasons, as they prevent open redirect vulnerabilities and ensure that authorization responses are only sent to trusted endpoints controlled by the client application.
    /// </summary>
    public ICollection<ClientRedirectUriEntity> RedirectUris { get; set; } = [];
    /// <summary>
    /// The collection of post-logout redirect URIs registered for the client. This collection contains instances of ClientPostLogoutUriEntity, which represent the individual post-logout redirect URIs that the client can use during the logout process. The authorization server will check this collection to validate the post_logout_redirect_uri parameter provided in logout requests and ensure that it matches one of the registered URIs for the client. Post-logout redirect URIs are used to redirect users back to a specified location after they have logged out of their session, providing a better user experience and allowing clients to perform any necessary cleanup or redirection after logout.
    /// </summary>
    public ICollection<ClientPostLogoutUriEntity> PostLogoutUris { get; set; } = [];
    /// <summary>
    /// The collection of scopes that the client is allowed to request. This collection contains instances of ClientScopeEntity, which represent the individual scopes (e.g., "openid", "profile", "email") that the client can include in its authorization requests. The authorization server will check this collection to determine if a client is authorized to request specific scopes during the authorization process. Clients must have at least one allowed scope to be able to obtain access tokens with permissions from the authorization server.
    /// </summary>
    public ICollection<ClientScopeEntity> AllowedScopes { get; set; } = [];
    /// <summary>
    /// The collection of CORS origins that the client is allowed to use. This collection contains instances of ClientCorsOriginEntity, which represent the individual CORS origins (e.g., "https://example.com") that the client can use when making cross-origin requests to the authorization server. The authorization server will check this collection to validate the Origin header in incoming requests and ensure that it matches one of the registered CORS origins for the client. This is important for security reasons, as it helps prevent cross-origin request forgery (CSRF) attacks and ensures that only trusted origins can interact with the authorization server on behalf of the client application.
    /// </summary>
    public ICollection<ClientCorsOriginEntity> CorsOrigins { get; set; } = [];
    /// <summary>
    /// The collection of claims associated with the client. This collection contains instances of ClientClaimEntity, which represent the individual claims (e.g., "role", "department") that can be included in tokens issued to the client. The authorization server can include these claims in access tokens or ID tokens based on the client's configuration and the scopes requested during the authorization process. Client claims can be used to provide additional information about the client application or to implement custom authorization logic based on the client's attributes.
    /// </summary>
    public ICollection<ClientClaimEntity> Claims { get; set; } = [];
}

/// <summary>
/// Represents a grant type that a client is allowed to use. This entity is associated with a specific client and indicates which OAuth2 grant types (e.g., "authorization_code", "client_credentials", "refresh_token") the client can use when making authorization requests. The authorization server will check this collection to determine if a client is authorized to use a specific grant type during the token request process. Each ClientGrantTypeEntity has a unique Id, a reference to the ClientId it belongs to, and the GrantType string that specifies the allowed grant type for that client.
/// </summary>
[Table("PulseAuth_ClientGrantTypes")]
public class ClientGrantTypeEntity
{
    /// <summary>
    /// The unique identifier for the client grant type entity. This is an auto-incrementing integer that serves as the primary key for the ClientGrantTypeEntity in the database. It is used to uniquely identify each grant type entry associated with a client and is typically generated by the database when a new record is inserted. The Id field is not exposed to clients and is only used internally by the authorization server to manage the relationships between clients and their allowed grant types.
    /// </summary>
    public int Id { get; set; }
    /// <summary>
    /// The identifier of the client that this grant type is associated with. This field is a foreign key that references the ClientId in the ClientEntity. It indicates which client application is allowed to use the specified grant type. The ClientId must match an existing client in the database, and it is used by the authorization server to look up the client's configuration when validating authorization requests and token requests. Each ClientGrantTypeEntity must be associated with a valid ClientId to ensure that the grant type is properly linked to a client application.
    /// </summary>
    public string ClientId { get; set; } = default!;
    /// <summary>
    /// The grant type that the client is allowed to use. This is a string that specifies the OAuth2 grant type (e.g., "authorization_code",
    /// </summary>
    [MaxLength(100)]
    public string GrantType { get; set; } = default!;
}

/// <summary>
/// Represents a redirect URI registered for a client. This entity is associated with a specific client and indicates which redirect URIs the client can use during the authorization process. The authorization server will check this collection to validate the redirect_uri parameter provided in authorization requests and ensure that it matches one of the registered URIs for the client. Redirect URIs are essential for security reasons, as they prevent open redirect vulnerabilities and ensure that authorization responses are only sent to trusted endpoints controlled by the client application. Each ClientRedirectUriEntity has a unique Id, a reference to the ClientId it belongs to, and the RedirectUri string that specifies the allowed redirect URI for that client.
/// </summary>
[Table("PulseAuth_ClientRedirectUris")]
public class ClientRedirectUriEntity
{
    /// <summary>
    /// The unique identifier for the client redirect URI entity. This is an auto-incrementing integer that serves as the primary key for the ClientRedirectUriEntity in the database. It is used to uniquely identify each redirect URI entry associated with a client and is typically generated by the database when a new record is inserted. The Id field is not exposed to clients and is only used internally by the authorization server to manage the relationships between clients and their registered redirect URIs.
    /// </summary>
    public int Id { get; set; }
    /// <summary>
    /// The identifier of the client that this redirect URI is associated with. This field is a foreign key that references the ClientId in the ClientEntity. It indicates which client application is allowed to use the specified redirect URI during the authorization process. The ClientId must match an existing client in the database, and it is used by the authorization server to look up the client's configuration when validating authorization requests and token requests. Each ClientRedirectUriEntity must be associated with a valid ClientId to ensure that the redirect URI is properly linked to a client application.
    /// </summary>
    public string ClientId { get; set; } = default!;
    /// <summary>
    /// The redirect URI that the client is allowed to use during the authorization process. This is a string that specifies a valid URI (e.g., "https://example.com/callback") that the client can use as the redirect_uri parameter in authorization requests. The authorization server will validate incoming authorization requests to ensure that the provided redirect_uri matches one of the registered URIs for the client, which helps prevent open redirect vulnerabilities and ensures that authorization responses are only sent to trusted endpoints controlled by the client application. The RedirectUri can be up to 2000 characters long and should be a well-formed URI.
    /// </summary>
    [MaxLength(2000)]
    public string RedirectUri { get; set; } = default!;
}

/// <summary>
/// Represents a post-logout redirect URI registered for a client. This entity is associated with a specific client and indicates which post-logout redirect URIs the client can use during the logout process. The authorization server will check this collection to validate the post_logout_redirect_uri parameter provided in logout requests and ensure that it matches one of the registered URIs for the client. Post-logout redirect URIs are used to redirect users back to a specified location after they have logged out of their session, providing a better user experience and allowing clients to perform any necessary cleanup or redirection after logout. Each ClientPostLogoutUriEntity has a unique Id, a reference to the ClientId it belongs to, and the PostLogoutUri string that specifies the allowed post-logout redirect URI for that client.
/// </summary>
[Table("PulseAuth_ClientPostLogoutUris")]
public class ClientPostLogoutUriEntity
{
    /// <summary>
    /// The unique identifier for the client post-logout redirect URI entity. This is an auto-incrementing integer that serves as the primary key for the ClientPostLogoutUriEntity in the database. It is used to uniquely identify each post-logout redirect URI entry associated with a client and is typically generated by the database when a new record is inserted. The Id field is not exposed to clients and is only used internally by the authorization server to manage the relationships between clients and their registered post-logout redirect URIs.
    /// </summary>
    public int Id { get; set; }
    /// <summary>
    /// The identifier of the client that this post-logout redirect URI is associated with. This field is a foreign key that references the ClientId in the ClientEntity. It indicates which client application is allowed to use the specified post-logout redirect URI during the logout process. The ClientId must match an existing client in the database, and it is used by the authorization server to look up the client's configuration when validating logout requests. Each ClientPostLogoutUriEntity must be associated with a valid ClientId to ensure that the post-logout redirect URI is properly linked to a client application.
    /// </summary>
    public string ClientId { get; set; } = default!;
    /// <summary>
    /// The post-logout redirect URI that the client is allowed to use during the logout process. This is a string that specifies a valid URI (e.g., "https://example.com/logout-callback") that the client can use as the post_logout_redirect_uri parameter in logout requests. The authorization server will validate incoming logout requests to ensure that the provided post_logout_redirect_uri matches one of the registered URIs for the client, which helps ensure that users are redirected to trusted endpoints controlled by the client application after logging out. The PostLogoutUri can be up to 2000 characters long and should be a well-formed URI.
    /// </summary>
    [MaxLength(2000)]
    public string PostLogoutUri { get; set; } = default!;
}

/// <summary>
/// Represents a scope that a client is allowed to request. This entity is associated with a specific client and indicates which scopes (e.g., "openid", "profile", "email") the client can include in its authorization requests. The authorization server will check this collection to determine if a client is authorized to request specific scopes during the authorization process. Clients must have at least one allowed scope to be able to obtain access tokens with permissions from the authorization server. Each ClientScopeEntity has a unique Id, a reference to the ClientId it belongs to, and the Scope string that specifies the allowed scope for that client.
/// </summary>
[Table("PulseAuth_ClientScopes")]
public class ClientScopeEntity
{
    /// <summary>
    /// The unique identifier for the client scope entity. This is an auto-incrementing integer that serves as the primary key for the ClientScopeEntity in the database. It is used to uniquely identify each scope entry associated with a client and is typically generated by the database when a new record is inserted. The Id field is not exposed to clients and is only used internally by the authorization server to manage the relationships between clients and their allowed scopes.
    /// </summary>
    public int Id { get; set; }
    /// <summary>
    /// The identifier of the client that this scope is associated with. This field is a foreign key that references the ClientId in the ClientEntity. It indicates which client application is allowed to request the specified scope during the authorization process. The ClientId must match an existing client in the database, and it is used by the authorization server to look up the client's configuration when validating authorization requests and token requests. Each ClientScopeEntity must be associated with a valid ClientId to ensure that the scope is properly linked to a client application.
    /// </summary>
    public string ClientId { get; set; } = default!;
    /// <summary>
    /// The scope that the client is allowed to request during the authorization process. This is a string that specifies a valid scope (e.g., "openid", "profile", "email") that the client can include in its authorization requests. The authorization server will validate incoming authorization requests to ensure that the requested scopes are included in this collection for the client, which helps determine what permissions the access token will have if the authorization process is successful. The Scope can be up to 200 characters long and should be a well-formed scope string.
    /// </summary>
    [MaxLength(200)]
    public string Scope { get; set; } = default!;
}

/// <summary>
/// Represents a CORS origin that a client is allowed to use. This entity is associated with a specific client and indicates which CORS origins (e.g., "https://example.com") the client can use when making cross-origin requests to the authorization server. The authorization server will check this collection to validate the Origin header in incoming requests and ensure that it matches one of the registered CORS origins for the client. This is important for security reasons, as it helps prevent cross-origin request forgery (CSRF) attacks and ensures that only trusted origins can interact with the authorization server on behalf of the client application. Each ClientCorsOriginEntity has a unique Id, a reference to the ClientId it belongs to, and the Origin string that specifies the allowed CORS origin for that client.
/// </summary>
[Table("PulseAuth_ClientCorsOrigins")]
public class ClientCorsOriginEntity
{
    /// <summary>
    /// The unique identifier for the client CORS origin entity. This is an auto-incrementing integer that serves as the primary key for the ClientCorsOriginEntity in the database. It is used to uniquely identify each CORS origin entry associated with a client and is typically generated by the database when a new record is inserted. The Id field is not exposed to clients and is only used internally by the authorization server to manage the relationships between clients and their registered CORS origins.
    /// </summary>
    public int Id { get; set; }
    /// <summary>
    /// The identifier of the client that this CORS origin is associated with. This field is a foreign key that references the ClientId in the ClientEntity. It indicates which client application is allowed to use the specified CORS origin when making cross-origin requests to the authorization server. The ClientId must match an existing client in the database, and it is used by the authorization server to look up the client's configuration when validating incoming requests. Each ClientCorsOriginEntity must be associated with a valid ClientId to ensure that the CORS origin is properly linked to a client application.
    /// </summary>
    public string ClientId { get; set; } = default!;
    /// <summary>
    /// The CORS origin that the client is allowed to use when making cross-origin requests to the authorization server. This is a string that specifies a valid origin (e.g., "https://example.com") that the client can use in the Origin header of its requests. The authorization server will validate incoming requests to ensure that the Origin header matches one of the registered CORS origins for the client, which helps prevent cross-origin request forgery (CSRF) attacks and ensures that only trusted origins can interact with the authorization server on behalf of the client application. The Origin can be up to 200 characters long and should be a well-formed origin string.
    /// </summary>
    [MaxLength(200)]
    public string Origin { get; set; } = default!;
}

/// <summary>
/// Represents a claim associated with a client. This entity is associated with a specific client and indicates which claims (e.g., "role", "department") can be included in tokens issued to the client. The authorization server can include these claims in access tokens or ID tokens based on the client's configuration and the scopes requested during the authorization process. Client claims can be used to provide additional information about the client application or to implement custom authorization logic based on the client's attributes. Each ClientClaimEntity has a unique Id, a reference to the ClientId it belongs to, and the Type and Value strings that specify the claim type and value for that client.
/// </summary>
[Table("PulseAuth_ClientClaims")]
public class ClientClaimEntity
{
    /// <summary>
    /// The unique identifier for the client claim entity. This is an auto-incrementing integer that serves as the primary key for the ClientClaimEntity in the database. It is used to uniquely identify each claim entry associated with a client and is typically generated by the database when a new record is inserted. The Id field is not exposed to clients and is only used internally by the authorization server to manage the relationships between clients and their associated claims.
    /// </summary>
    public int Id { get; set; }
    /// <summary>
    /// The identifier of the client that this claim is associated with. This field is a foreign key that references the ClientId in the ClientEntity. It indicates which client application is associated with the specified claim. The ClientId must match an existing client in the database, and it is used by the authorization server to look up the client's configuration when validating authorization requests and token requests. Each ClientClaimEntity must be associated with a valid ClientId to ensure that the claim is properly linked to a client application.
    /// </summary>
    public string ClientId { get; set; } = default!;
    /// <summary>
    /// The type of the claim associated with the client. This is a string that specifies the claim type (e.g., "role", "department") that can be included in tokens issued to the client. The authorization server can include this claim in access tokens or ID tokens based on the client's configuration and the scopes requested during the authorization process. The Type can be up to 200 characters long and should be a well-formed claim type string.
    /// </summary>
    [MaxLength(200)]
    public string Type { get; set; } = default!;
    /// <summary>
    /// The value of the claim associated with the client. This is a string that specifies the claim value (e.g., "admin", "sales") that can be included in tokens issued to the client. The authorization server can include this claim in access tokens or ID tokens based on the client's configuration and the scopes requested during the authorization process. The Value can be up to 1000 characters long and should be a well-formed claim value string.
    /// </summary>
    [MaxLength(1000)]
    public string Value { get; set; } = default!;
}
