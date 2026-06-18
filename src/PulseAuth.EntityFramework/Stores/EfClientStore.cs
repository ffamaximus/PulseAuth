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

    /// <summary>
    /// Initializes a new instance of the <see cref="EfClientStore"/> class with the specified database context. The database context is used to access the Clients table and related entities (e.g., grant types, redirect URIs, allowed scopes) to retrieve client information based on the client_id. This constructor is typically called by dependency injection when you register the service in your application's service container. Make sure to configure your DbContext properly and apply any necessary migrations to ensure that the Clients table and related entities are available in the database before using this client store implementation.
    /// </summary>
    /// <param name="db"></param>
    public EfClientStore(PulseAuthDbContext db) => _db = db;

    /// <summary>
    /// Finds a client by its unique identifier (client_id). This method queries the database for a client entity that matches the provided client_id and is enabled. It includes related entities such as grant types, redirect URIs, post-logout redirect URIs, allowed scopes, CORS origins, and claims to construct a complete Client object. If a matching client is found, it returns a Client instance populated with the retrieved data; otherwise, it returns null. The method uses asynchronous database operations to ensure non-blocking calls and accepts a CancellationToken to allow for cancellation of the operation if needed.
    /// </summary>
    /// <param name="clientId"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
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
