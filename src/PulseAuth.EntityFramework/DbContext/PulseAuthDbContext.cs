using Microsoft.EntityFrameworkCore;
using PulseAuth.EntityFramework.Entities;

namespace PulseAuth.EntityFramework.DbContext;

/// <summary>
/// EF Core DbContext for PulseAuth persistent stores.
/// Add this to your application's DbContext or use it standalone.
/// </summary>
public class PulseAuthDbContext : Microsoft.EntityFrameworkCore.DbContext
{
    public PulseAuthDbContext(DbContextOptions<PulseAuthDbContext> options) : base(options) { }

    // Clients
    public DbSet<ClientEntity>           Clients          { get; set; } = default!;
    public DbSet<ClientGrantTypeEntity>  ClientGrantTypes { get; set; } = default!;
    public DbSet<ClientRedirectUriEntity> ClientRedirectUris { get; set; } = default!;
    public DbSet<ClientPostLogoutUriEntity> ClientPostLogoutUris { get; set; } = default!;
    public DbSet<ClientScopeEntity>      ClientScopes     { get; set; } = default!;
    public DbSet<ClientCorsOriginEntity> ClientCorsOrigins { get; set; } = default!;
    public DbSet<ClientClaimEntity>      ClientClaims     { get; set; } = default!;

    // Grants
    public DbSet<AuthorizationCodeEntity> AuthorizationCodes { get; set; } = default!;
    public DbSet<RefreshTokenEntity>      RefreshTokens       { get; set; } = default!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ClientEntity>(e =>
        {
            e.HasIndex(c => c.ClientId).IsUnique();
        });

        builder.Entity<ClientGrantTypeEntity>(e =>
        {
            e.HasIndex(x => new { x.ClientId, x.GrantType }).IsUnique();
        });

        builder.Entity<ClientRedirectUriEntity>(e =>
        {
        });

        builder.Entity<ClientPostLogoutUriEntity>(e =>
        {
        });

        builder.Entity<ClientScopeEntity>(e =>
        {
            e.HasIndex(x => new { x.ClientId, x.Scope }).IsUnique();
        });

        builder.Entity<ClientCorsOriginEntity>(e =>
        {
        });

        builder.Entity<ClientClaimEntity>(e =>
        {
        });

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
