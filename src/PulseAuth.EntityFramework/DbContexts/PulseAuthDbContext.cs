using Microsoft.EntityFrameworkCore;
using PulseAuth.EntityFramework.Entities;

namespace PulseAuth.EntityFramework.DbContexts;

/// <summary>
/// EF Core DbContext for PulseAuth persistent stores.
/// Can be used standalone or inherited by your application's DbContext to consolidate schemas.
/// </summary>
/// <example>
/// Standalone:
/// <code>
/// builder.Services.AddPulseAuth(...)
///     .AddEntityFrameworkStores(opts => opts.UseMySql(cs, version));
/// </code>
/// Inherited (single context for your app + PulseAuth tables):
/// <code>
/// public class AppDbContext : PulseAuthDbContext
/// {
///     public AppDbContext(DbContextOptions&lt;AppDbContext&gt; options) : base(options) { }
///     // your own DbSets here
/// }
/// </code>
/// </example>
public class PulseAuthDbContext : DbContext
{
    /// <summary>Standalone usage — registered directly via AddEntityFrameworkStores.</summary>
    public PulseAuthDbContext(DbContextOptions<PulseAuthDbContext> options) : base(options) { }

    /// <summary>
    /// Inheritance constructor — used when a derived context (e.g. AppDbContext) passes its
    /// own <see cref="DbContextOptions{TContext}"/> up the chain.
    /// EF Core resolves <c>DbContextOptions&lt;AppDbContext&gt;</c> from DI and passes it here.
    /// </summary>
    protected PulseAuthDbContext(DbContextOptions options) : base(options) { }


    // Clients
    /// <summary>
    /// The Clients DbSet represents the collection of client applications that are registered with the authorization server. Each ClientEntity in this DbSet contains information about a specific client, such as its client_id, allowed grant types, redirect URIs, allowed scopes, and other configuration settings. This DbSet is used to store and retrieve client information during the authorization process, allowing the server to validate incoming requests based on the client's configuration. The related entities (ClientGrantTypeEntity, ClientRedirectUriEntity, etc.) represent the various aspects of a client's configuration and are linked to the ClientEntity through foreign key relationships.
    /// </summary>
    public DbSet<ClientEntity>           Clients          { get; set; } = default!;
    /// <summary>
    /// The ClientGrantTypes DbSet represents the collection of grant types that are allowed for each client application. Each ClientGrantTypeEntity in this DbSet contains information about a specific grant type (e.g., "authorization_code", "client_credentials") that is associated with a particular client. This DbSet is used to store and retrieve the allowed grant types for each client, which is essential for validating incoming token requests and ensuring that clients can only use the grant types they are authorized for. The combination of ClientId and GrantType is unique, meaning that a client cannot have duplicate entries for the same grant type.
    /// </summary>
    public DbSet<ClientGrantTypeEntity>  ClientGrantTypes { get; set; } = default!;
    /// <summary>
    /// The ClientRedirectUris DbSet represents the collection of redirect URIs that are registered for each client application. Each ClientRedirectUriEntity in this DbSet contains information about a specific redirect URI that is associated with a particular client. This DbSet is used to store and retrieve the allowed redirect URIs for each client, which is essential for validating incoming authorization requests and ensuring that clients can only redirect users to authorized locations after successful authentication. The redirect URIs are typically used in the Authorization Code flow to specify where the authorization server should send the user after they have authenticated and authorized the client.
    /// </summary>
    public DbSet<ClientRedirectUriEntity> ClientRedirectUris { get; set; } = default!;
    /// <summary>
    /// The ClientPostLogoutUris DbSet represents the collection of post-logout redirect URIs that are registered for each client application. Each ClientPostLogoutUriEntity in this DbSet contains information about a specific post-logout redirect URI that is associated with a particular client. This DbSet is used to store and retrieve the allowed post-logout redirect URIs for each client, which is essential for validating incoming logout requests and ensuring that clients can only redirect users to authorized locations after they have logged out. The post-logout redirect URIs are typically used in OpenID Connect flows to specify where the authorization server should send the user after they have logged out of their session.
    /// </summary>
    public DbSet<ClientPostLogoutUriEntity> ClientPostLogoutUris { get; set; } = default!;
    /// <summary>
    /// The ClientScopes DbSet represents the collection of scopes that are allowed for each client application. Each ClientScopeEntity in this DbSet contains information about a specific scope (e.g., "openid", "profile", "email") that is associated with a particular client. This DbSet is used to store and retrieve the allowed scopes for each client, which is essential for validating incoming authorization requests and ensuring that clients can only request permissions that they are authorized for. The combination of ClientId and Scope is unique, meaning that a client cannot have duplicate entries for the same scope.
    /// </summary>
    public DbSet<ClientScopeEntity>      ClientScopes     { get; set; } = default!;
    /// <summary>
    /// The ClientCorsOrigins DbSet represents the collection of CORS origins that are registered for each client application. Each ClientCorsOriginEntity in this DbSet contains information about a specific CORS origin (e.g., "https://example.com") that is associated with a particular client. This DbSet is used to store and retrieve the allowed CORS origins for each client, which is essential for validating incoming cross-origin requests and ensuring that clients can only make API calls from authorized origins. The CORS origins are typically used in single-page applications (SPAs) to specify which domains are allowed to access the authorization server's APIs from the browser.
    /// </summary>
    public DbSet<ClientCorsOriginEntity> ClientCorsOrigins { get; set; } = default!;
    /// <summary>
    /// The ClientClaims DbSet represents the collection of claims that are associated with each client application. Each ClientClaimEntity in this DbSet contains information about a specific claim (e.g., "role", "department") that is associated with a particular client. This DbSet is used to store and retrieve the claims for each client, which can be included in ID tokens or access tokens issued to that client. The claims can provide additional information about the client or its permissions, and can be used by resource servers to make authorization decisions based on the client's attributes.
    /// </summary>
    public DbSet<ClientClaimEntity>      ClientClaims     { get; set; } = default!;

    // Grants
    /// <summary>
    /// The AuthorizationCodes DbSet represents the collection of authorization codes that have been issued by the authorization server. Each AuthorizationCodeEntity in this DbSet contains information about a specific authorization code, such as the code value, associated client_id, subject_id (user), scopes, expiration time, and any additional data needed to complete the authorization process. This DbSet is used to store and retrieve authorization codes during the Authorization Code flow, allowing the server to validate incoming token requests that include an authorization code and exchange it for an access token (and optionally an ID token). The authorization codes are typically short-lived and can only be used once, so they should be securely stored and removed after use or expiration.
    /// </summary>
    public DbSet<AuthorizationCodeEntity> AuthorizationCodes { get; set; } = default!;
    /// <summary>
    /// The RefreshTokens DbSet represents the collection of refresh tokens that have been issued by the authorization server. Each RefreshTokenEntity in this DbSet contains information about a specific refresh token, such as the token value, associated client_id, subject_id (user), scopes, expiration time, and any additional data needed to manage the refresh token lifecycle. This DbSet is used to store and retrieve refresh tokens during the Refresh Token flow, allowing the server to validate incoming token requests that include a refresh token and exchange it for a new access token (and optionally a new refresh token). The refresh tokens are typically long-lived and should be securely stored by the client, as they can be used to obtain new access tokens without requiring the user to re-authenticate.
    /// </summary>
    public DbSet<RefreshTokenEntity>      RefreshTokens       { get; set; } = default!;

    /// <summary>
    /// Configures the entity relationships and indexes for the PulseAuthDbContext. This method is called by EF Core when the model is being created and allows you to specify how the entities are mapped to the database schema. In this implementation, we define unique indexes on certain properties (e.g., ClientId for ClientEntity, combination of ClientId and GrantType for ClientGrantTypeEntity) to ensure data integrity and optimize query performance. We also define indexes on properties that are commonly queried (e.g., SubjectId and ExpiresAt for AuthorizationCodeEntity and RefreshTokenEntity) to improve the efficiency of lookups during the authorization process. The relationships between entities (e.g., foreign keys) can also be configured here if needed, although in this implementation we rely on conventions for most of the relationships.
    /// </summary>
    /// <param name="builder"></param>
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // ── Clients ──────────────────────────────────────────────────────────
        builder.Entity<ClientEntity>(e =>
        {
            e.HasIndex(c => c.ClientId).IsUnique();

            e.HasMany(c => c.GrantTypes)
             .WithOne()
             .HasForeignKey(x => x.ClientId)
             .OnDelete(DeleteBehavior.Cascade);

            e.HasMany(c => c.RedirectUris)
             .WithOne()
             .HasForeignKey(x => x.ClientId)
             .OnDelete(DeleteBehavior.Cascade);

            e.HasMany(c => c.PostLogoutUris)
             .WithOne()
             .HasForeignKey(x => x.ClientId)
             .OnDelete(DeleteBehavior.Cascade);

            e.HasMany(c => c.AllowedScopes)
             .WithOne()
             .HasForeignKey(x => x.ClientId)
             .OnDelete(DeleteBehavior.Cascade);

            e.HasMany(c => c.CorsOrigins)
             .WithOne()
             .HasForeignKey(x => x.ClientId)
             .OnDelete(DeleteBehavior.Cascade);

            e.HasMany(c => c.Claims)
             .WithOne()
             .HasForeignKey(x => x.ClientId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<ClientGrantTypeEntity>(e =>
        {
            e.HasIndex(x => new { x.ClientId, x.GrantType }).IsUnique();
        });

        builder.Entity<ClientScopeEntity>(e =>
        {
            e.HasIndex(x => new { x.ClientId, x.Scope }).IsUnique();
        });

        // ── Persisted grants ─────────────────────────────────────────────────
        builder.Entity<AuthorizationCodeEntity>(e =>
        {
            e.HasIndex(x => x.SubjectId);
            e.HasIndex(x => x.ExpiresAt);
        });

        builder.Entity<RefreshTokenEntity>(e =>
        {
            e.HasIndex(x => new { x.SubjectId, x.ClientId });
            e.HasIndex(x => x.ExpiresAt);
        });
    }
}
