using Microsoft.EntityFrameworkCore;
using PulseAuth.EntityFramework.Entities;

namespace PulseAuth.EntityFramework.DbContexts;

/// <summary>
/// Shared EF Core model configuration for PulseAuth entities.
/// Called from <see cref="PulseAuthDbContext.OnModelCreating"/> and
/// <see cref="PulseAuthIdentityDbContext{TUser}.OnModelCreating"/> so that
/// both context types produce identical PulseAuth table schemas.
/// </summary>
internal static class PulseAuthModelConfiguration
{
    internal static void Apply(ModelBuilder builder)
    {
        // ── Clients ──────────────────────────────────────────────────────────
        builder.Entity<ClientEntity>(e =>
        {
            e.HasIndex(c => c.ClientId).IsUnique();

            e.HasMany(c => c.GrantTypes)
             .WithOne().HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);

            e.HasMany(c => c.RedirectUris)
             .WithOne().HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);

            e.HasMany(c => c.PostLogoutUris)
             .WithOne().HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);

            e.HasMany(c => c.AllowedScopes)
             .WithOne().HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);

            e.HasMany(c => c.CorsOrigins)
             .WithOne().HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);

            e.HasMany(c => c.Claims)
             .WithOne().HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<ClientGrantTypeEntity>(e =>
            e.HasIndex(x => new { x.ClientId, x.GrantType }).IsUnique());

        builder.Entity<ClientScopeEntity>(e =>
            e.HasIndex(x => new { x.ClientId, x.Scope }).IsUnique());

        // ── Grants ────────────────────────────────────────────────────────────
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

        builder.Entity<ReferenceTokenEntity>(e =>
        {
            e.HasIndex(x => new { x.SubjectId, x.ClientId });
            e.HasIndex(x => x.ExpiresAt);
        });

        builder.Entity<ConsentEntity>(e =>
            e.HasIndex(x => new { x.SubjectId, x.ClientId }).IsUnique());
    }
}
