using Microsoft.EntityFrameworkCore;
using PulseAuth.Abstractions;
using PulseAuth.EntityFramework.Abstractions;
using PulseAuth.EntityFramework.Entities;
using PulseAuth.Helpers;
using PulseAuth.Models;

namespace PulseAuth.EntityFramework.Stores;

/// <summary>EF Core-backed <see cref="IReferenceTokenStore"/>. Only a hash of the handle is stored.</summary>
public class EfReferenceTokenStore : IReferenceTokenStore
{
    private readonly IPulseAuthDbContext _db;

    /// <summary>Initializes a new instance of the <see cref="EfReferenceTokenStore"/> class.</summary>
    public EfReferenceTokenStore(IPulseAuthDbContext db) => _db = db ?? throw new ArgumentNullException(nameof(db));

    /// <inheritdoc />
    public async Task StoreAsync(ReferenceToken token, CancellationToken ct = default)
    {
        _db.ReferenceTokens.Add(new ReferenceTokenEntity
        {
            Key       = GrantKeyHelper.ToStorageKey(token.Handle),
            ClientId  = token.ClientId,
            SubjectId = token.SubjectId,
            Data      = token.Jwt,
            CreatedAt = token.CreatedAt,
            ExpiresAt = token.ExpiresAt,
        });
        await _db.SaveChangesAsync(ct);
    }

    /// <inheritdoc />
    public async Task<ReferenceToken?> FindAsync(string handle, CancellationToken ct = default)
    {
        var key = GrantKeyHelper.ToStorageKey(handle);
        var e = await _db.ReferenceTokens.AsNoTracking().FirstOrDefaultAsync(t => t.Key == key, ct);
        return e is null ? null : new ReferenceToken
        {
            Handle = handle, ClientId = e.ClientId, SubjectId = e.SubjectId,
            Jwt = e.Data, CreatedAt = e.CreatedAt, ExpiresAt = e.ExpiresAt,
        };
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string handle, CancellationToken ct = default)
    {
        var key = GrantKeyHelper.ToStorageKey(handle);
        await _db.ReferenceTokens.Where(t => t.Key == key).ExecuteDeleteAsync(ct);
    }

    /// <inheritdoc />
    public async Task RemoveBySubjectAsync(string subjectId, string clientId, CancellationToken ct = default)
        => await _db.ReferenceTokens
            .Where(t => t.SubjectId == subjectId && t.ClientId == clientId)
            .ExecuteDeleteAsync(ct);

    /// <inheritdoc />
    public async Task RemoveExpiredAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        await _db.ReferenceTokens.Where(t => t.ExpiresAt < now).ExecuteDeleteAsync(ct);
    }
}
