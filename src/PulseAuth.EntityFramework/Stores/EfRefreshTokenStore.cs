using Microsoft.EntityFrameworkCore;
using PulseAuth.Abstractions;
using PulseAuth.EntityFramework.DbContext;
using PulseAuth.EntityFramework.Entities;
using PulseAuth.Models;

namespace PulseAuth.EntityFramework.Stores;

public class EfRefreshTokenStore : IRefreshTokenStore
{
    private readonly PulseAuthDbContext _db;

    public EfRefreshTokenStore(PulseAuthDbContext db) => _db = db;

    public async Task StoreAsync(RefreshToken token, CancellationToken ct = default)
    {
        _db.RefreshTokens.Add(new RefreshTokenEntity
        {
            Key             = token.Token,
            ClientId        = token.ClientId,
            SubjectId       = token.SubjectId,
            Scopes          = string.Join(" ", token.Scopes),
            CreatedAt       = token.CreatedAt,
            ExpiresAt       = token.ExpiresAt,
            PreviousTokenId = token.PreviousTokenId,
        });
        await _db.SaveChangesAsync(ct);
    }

    public async Task<RefreshToken?> FindByTokenAsync(string token, CancellationToken ct = default)
    {
        var e = await _db.RefreshTokens
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Key == token, ct);

        if (e is null) return null;

        return new RefreshToken
        {
            Token           = e.Key,
            ClientId        = e.ClientId,
            SubjectId       = e.SubjectId,
            Scopes          = e.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            CreatedAt       = e.CreatedAt,
            ExpiresAt       = e.ExpiresAt,
            IsConsumed      = e.IsConsumed,
            PreviousTokenId = e.PreviousTokenId,
        };
    }

    public async Task ConsumeAsync(string token, CancellationToken ct = default)
    {
        await _db.RefreshTokens
            .Where(t => t.Key == token)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.IsConsumed, true), ct);
    }

    public async Task RevokeBySubjectAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        await _db.RefreshTokens
            .Where(t => t.SubjectId == subjectId && t.ClientId == clientId && !t.IsConsumed)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.IsConsumed, true), ct);
    }

    public async Task RemoveExpiredAsync(CancellationToken ct = default)
    {
        var cutoff = DateTime.UtcNow;
        await _db.RefreshTokens
            .Where(t => t.ExpiresAt < cutoff || t.IsConsumed)
            .ExecuteDeleteAsync(ct);
    }
}
