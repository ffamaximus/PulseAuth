using Microsoft.EntityFrameworkCore;
using PulseAuth.EntityFramework.Entities;

namespace PulseAuth.EntityFramework.Abstractions;

/// <summary>
/// Exposes the PulseAuth DbSets independently of the context inheritance chain.
/// Both <see cref="PulseAuth.EntityFramework.DbContexts.PulseAuthDbContext"/> (standalone)
/// and <see cref="PulseAuth.EntityFramework.DbContexts.PulseAuthIdentityDbContext{TUser}"/>
/// (combined with ASP.NET Core Identity) implement this interface, allowing the EF stores
/// to work with either pattern without depending on a concrete class.
/// </summary>
public interface IPulseAuthDbContext
{
    // ── Clients ──────────────────────────────────────────────────────────────
    /// <summary>
    /// The clients registered in the system. This includes all client details such as allowed grant types,
    /// </summary>
    DbSet<ClientEntity> Clients { get; }
    /// <summary>
    /// The allowed grant types for each client. This table is used to determine which OAuth2 flows a client can use during the authorization process. Each entry in this table links a client to a specific grant type (e.g., "authorization_code", "client_credentials", "password", "refresh_token") that the client is allowed to use when requesting access tokens. During the validation of an authorization request, the system checks this table to ensure that the client's requested grant type is permitted based on its configuration.
    /// </summary>
    DbSet<ClientGrantTypeEntity> ClientGrantTypes { get; }
    /// <summary>
    /// The redirect URIs registered for each client. This table is used to validate the redirect_uri parameter in authorization requests. Each entry links a client to a specific redirect URI that the client has registered. During the authorization process, when a client initiates an authorization request, the system checks this table to ensure that the provided redirect_uri matches one of the URIs registered for that client. This validation is crucial for preventing open redirect vulnerabilities and ensuring that authorization responses are only sent to trusted endpoints controlled by the client application.
    /// </summary>
    DbSet<ClientRedirectUriEntity> ClientRedirectUris { get; }
    /// <summary>
    /// The post-logout redirect URIs registered for each client. This table is used to validate the post_logout_redirect_uri parameter in logout requests. Each entry links a client to a specific post-logout redirect URI that the client has registered. During the logout process, when a client initiates a logout request, the system checks this table to ensure that the provided post_logout_redirect_uri matches one of the URIs registered for that client. This validation helps ensure that after a user logs out, they are redirected to a trusted endpoint controlled by the client application, preventing potential open redirect vulnerabilities and ensuring a secure logout flow.
    /// </summary>
    DbSet<ClientPostLogoutUriEntity> ClientPostLogoutUris { get; }
    /// <summary>
    /// The allowed scopes for each client. This table is used to determine which API scopes a client can request access to during the authorization process. Each entry in this table links a client to a specific scope (e.g., "read", "write", "openid", "profile") that the client is allowed to request when initiating an authorization request. During the validation of an authorization request, the system checks this table to ensure that the client's requested scopes are permitted based on its configuration. This helps enforce fine-grained access control and ensures that clients can only request permissions that they are authorized for.
    /// </summary>
    DbSet<ClientScopeEntity> ClientScopes { get; }
    /// <summary>
    /// The allowed CORS origins for each client. This table is used to determine which origins are permitted to make cross-origin requests to the authorization server on behalf of a client application. Each entry in this table links a client to a specific CORS origin (e.g., "https://example.com") that is allowed to interact with the authorization server when making API requests from a browser context. During the processing of API requests, the system checks this table to ensure that the origin of the request is allowed for the specified client, which helps prevent unauthorized cross-origin interactions and enhances the security of the authorization server.
    /// </summary>
    DbSet<ClientCorsOriginEntity> ClientCorsOrigins { get; }
    /// <summary>
    /// The claims associated with each client. This table is used to store custom claims that can be included in tokens issued to clients. Each entry in this table links a client to a specific claim type and value (e.g., "role": "admin", "department": "sales") that can be used to provide additional information about the client in the access token or ID token. During the token issuance process, the system retrieves these claims and includes them in the issued tokens as needed, allowing for more flexible and customizable token contents based on the client's configuration.
    /// </summary>
    DbSet<ClientClaimEntity> ClientClaims { get; }

    // ── Grants ────────────────────────────────────────────────────────────────
    /// <summary>
    /// The authorization codes issued to clients during the Authorization Code flow. This table is used to store temporary authorization codes that are generated when a user successfully authorizes a client application. Each entry in this table contains information about the authorization code, such as the associated client, user, scopes, and expiration time. During the token exchange process, when a client presents an authorization code to obtain an access token, the system checks this table to validate the code and ensure that it is still valid (i.e., not expired or already used) before issuing tokens to the client. This helps maintain the security of the Authorization Code flow by ensuring that only valid and authorized codes can be exchanged for tokens.
    /// </summary>
    DbSet<AuthorizationCodeEntity> AuthorizationCodes { get; }
    /// <summary>
    /// The refresh tokens issued to clients during the Refresh Token flow. This table is used to store long-lived refresh tokens that are generated when a client successfully obtains an access token with the "offline_access" scope. Each entry in this table contains information about the refresh token, such as the associated client, user, scopes, and expiration time. During the token refresh process, when a client presents a refresh token to obtain a new access token, the system checks this table to validate the refresh token and ensure that it is still valid (i.e., not expired or revoked) before issuing new tokens to the client. This helps maintain the security of the Refresh Token flow by ensuring that only valid and authorized refresh tokens can be used to obtain new access tokens.
    /// </summary>
    DbSet<RefreshTokenEntity> RefreshTokens { get; }

    /// <summary>Reference (opaque) access tokens (1.4.0+).</summary>
    DbSet<ReferenceTokenEntity> ReferenceTokens { get; }

    /// <summary>User consents (1.4.0+).</summary>
    DbSet<ConsentEntity> Consents { get; }

    /// <summary>
    /// Saves all changes made in this context to the database. This method is used to persist any modifications made to the entities tracked by the context, such as adding new clients, updating existing client configurations, storing authorization codes, or managing refresh tokens. The method returns the number of state entries written to the database, which can be used to confirm that the expected changes were successfully saved. It also accepts a CancellationToken to allow for cancellation of the save operation if needed, which can be useful in scenarios where the operation may take a long time or when the application is shutting down.
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
