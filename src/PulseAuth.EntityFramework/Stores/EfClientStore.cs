using Microsoft.EntityFrameworkCore;
using PulseAuth.Abstractions;
using PulseAuth.EntityFramework.DbContext;
using PulseAuth.Models;

namespace PulseAuth.EntityFramework.Stores;

/// <summary>
/// EF Core-backed <see cref="IClientStore"/>.
/// </summary>
public class EfClientStore : IClientStore
{
    private readonly PulseAuthDbContext _db;

    public EfClientStore(PulseAuthDbContext db) => _db = db;

    public async Task<Client?> FindClientByIdAsync(string clientId, CancellationToken ct = default)
    {
        var entity = await _db.Clients
            .Include(c => c.GrantTypes)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.AllowedScopes)
            .Include(c => c.CorsOrigins)
            .Include(c => c.Claims)
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientId == clientId && c.Enabled, ct);

        if (entity is null) return null;

        return new Client
        {
            ClientId                 = entity.ClientId,
            ClientSecretHash         = entity.ClientSecretHash,
            ClientName               = entity.ClientName,
            Description              = entity.Description,
            LogoUri                  = entity.LogoUri,
            Enabled                  = entity.Enabled,
            RequirePkce              = entity.RequirePkce,
            AllowOfflineAccess       = entity.AllowOfflineAccess,
            RequireConsent           = entity.RequireConsent,
            AccessTokenLifetime      = entity.AccessTokenLifetime,
            RefreshTokenLifetime     = entity.RefreshTokenLifetime,
            AuthorizationCodeLifetime = entity.AuthorizationCodeLifetime,
            IdentityTokenLifetime    = entity.IdentityTokenLifetime,
            AllowedGrantTypes        = entity.GrantTypes.Select(g => g.GrantType).ToList(),
            RedirectUris             = entity.RedirectUris.Select(r => r.RedirectUri).ToList(),
            PostLogoutRedirectUris   = entity.PostLogoutUris.Select(p => p.PostLogoutUri).ToList(),
            AllowedScopes            = entity.AllowedScopes.Select(s => s.Scope).ToList(),
            AllowedCorsOrigins       = entity.CorsOrigins.Select(c => c.Origin).ToList(),
            Claims                   = entity.Claims.ToDictionary(c => c.Type, c => c.Value),
        };
    }
}
