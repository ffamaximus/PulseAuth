using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PulseAuth.EntityFramework.Abstractions;
using PulseAuth.EntityFramework.Entities;

namespace PulseAuth.EntityFramework.DbContexts;

/// <summary>
/// Combined EF Core DbContext that merges ASP.NET Core Identity tables
/// (<c>AspNetUsers</c>, <c>AspNetRoles</c>, etc.) with PulseAuth tables
/// (<c>PulseAuth_Clients</c>, <c>PulseAuth_AuthorizationCodes</c>, etc.)
/// into a single migration.
/// </summary>
/// <typeparam name="TUser">
/// Your <see cref="IdentityUser"/> (or a derived class) — the same type you pass to
/// <c>AddIdentity&lt;TUser, TRole&gt;()</c> in Program.cs.
/// </typeparam>
/// <example>
/// <code>
/// // AuthDbContext.cs
/// public class AuthDbContext : PulseAuthIdentityDbContext&lt;IdentityUser&gt;
/// {
///     public AuthDbContext(DbContextOptions&lt;AuthDbContext&gt; options) : base(options) { }
/// }
///
/// // Program.cs
/// builder.Services
///     .AddIdentity&lt;IdentityUser, IdentityRole&gt;()
///     .AddEntityFrameworkStores&lt;AuthDbContext&gt;();
///
/// builder.Services.AddPulseAuth(...)
///     .AddEntityFrameworkStores&lt;AuthDbContext&gt;();
///
/// // Design-time factory (in your startup project)
/// public class AuthDbContextFactory : IDesignTimeDbContextFactory&lt;AuthDbContext&gt;
/// {
///     public AuthDbContext CreateDbContext(string[] args)
///     {
///         var opts = new DbContextOptionsBuilder&lt;AuthDbContext&gt;()
///             .UseMySql("...", new MariaDbServerVersion(new Version(10, 6)))
///             .Options;
///         return new AuthDbContext(opts);
///     }
/// }
/// </code>
/// </example>
public abstract class PulseAuthIdentityDbContext<TUser>
    : IdentityDbContext<TUser>, IPulseAuthDbContext
    where TUser : IdentityUser
{
    /// <inheritdoc />
    protected PulseAuthIdentityDbContext(DbContextOptions options) : base(options) { }

    // ── Clients ──────────────────────────────────────────────────────────────

    /// <inheritdoc cref="IPulseAuthDbContext.Clients"/>
    public DbSet<ClientEntity>              Clients              { get; set; } = default!;

    /// <inheritdoc cref="IPulseAuthDbContext.ClientGrantTypes"/>
    public DbSet<ClientGrantTypeEntity>     ClientGrantTypes     { get; set; } = default!;

    /// <inheritdoc cref="IPulseAuthDbContext.ClientRedirectUris"/>
    public DbSet<ClientRedirectUriEntity>   ClientRedirectUris   { get; set; } = default!;

    /// <inheritdoc cref="IPulseAuthDbContext.ClientPostLogoutUris"/>
    public DbSet<ClientPostLogoutUriEntity> ClientPostLogoutUris { get; set; } = default!;

    /// <inheritdoc cref="IPulseAuthDbContext.ClientScopes"/>
    public DbSet<ClientScopeEntity>         ClientScopes         { get; set; } = default!;

    /// <inheritdoc cref="IPulseAuthDbContext.ClientCorsOrigins"/>
    public DbSet<ClientCorsOriginEntity>    ClientCorsOrigins    { get; set; } = default!;

    /// <inheritdoc cref="IPulseAuthDbContext.ClientClaims"/>
    public DbSet<ClientClaimEntity>         ClientClaims         { get; set; } = default!;

    // ── Grants ────────────────────────────────────────────────────────────────

    /// <inheritdoc cref="IPulseAuthDbContext.AuthorizationCodes"/>
    public DbSet<AuthorizationCodeEntity>   AuthorizationCodes   { get; set; } = default!;

    /// <inheritdoc cref="IPulseAuthDbContext.RefreshTokens"/>
    public DbSet<RefreshTokenEntity>        RefreshTokens        { get; set; } = default!;

    /// <summary>Reference (opaque) access tokens.</summary>
    public DbSet<ReferenceTokenEntity>      ReferenceTokens      { get; set; } = default!;

    /// <summary>User consents.</summary>
    public DbSet<ConsentEntity>             Consents             { get; set; } = default!;

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder builder)
    {
        // Configure Identity tables (AspNetUsers, AspNetRoles, etc.)
        base.OnModelCreating(builder);

        // Configure PulseAuth tables using shared configuration
        PulseAuthModelConfiguration.Apply(builder);
    }
}
