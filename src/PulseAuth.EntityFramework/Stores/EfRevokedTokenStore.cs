using Microsoft.EntityFrameworkCore;
using PulseAuth.Abstractions;
using PulseAuth.EntityFramework.Abstractions;
using PulseAuth.EntityFramework.Entities;

namespace PulseAuth.EntityFramework.Stores;

/// <summary>EF Core <see cref="IRevokedTokenStore"/> (table <c>PulseAuth_RevokedTokens</c>).</summary>
public class EfRevokedTokenStore : IRevokedTokenStore
{
    private readonly IPulseAuthDbContext _db;

    /// <summary>Creates the store.</summary>
    public EfRevokedTokenStore(IPulseAuthDbContext db) => _db = db ?? throw new ArgumentNullException(nameof(db));

    /// <inheritdoc />
    public async Task RevokeAsync(string tokenId, DateTime expiresAt, CancellationToken ct = default)
    {
        // Idempotent: extend an existing entry instead of failing on the primary key.
        var updated = await _db.RevokedTokens
            .Where(t => t.Key == tokenId && t.ExpiresAt < expiresAt)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.ExpiresAt, expiresAt), ct);
        if (updated > 0 || await _db.RevokedTokens.AnyAsync(t => t.Key == tokenId, ct))
            return;

        _db.RevokedTokens.Add(new RevokedTokenEntity { Key = tokenId, ExpiresAt = expiresAt, CreatedAt = DateTime.UtcNow });
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // A concurrent request inserted the same id: it is revoked either way.
        }
    }

    /// <inheritdoc />
    public async Task<bool> IsRevokedAsync(string tokenId, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        return await _db.RevokedTokens.AsNoTracking().AnyAsync(t => t.Key == tokenId && t.ExpiresAt > now, ct);
    }

    /// <inheritdoc />
    public async Task RemoveExpiredAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        await _db.RevokedTokens.Where(t => t.ExpiresAt <= now).ExecuteDeleteAsync(ct);
    }
}
