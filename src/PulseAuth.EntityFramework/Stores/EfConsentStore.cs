using Microsoft.EntityFrameworkCore;
using PulseAuth.Abstractions;
using PulseAuth.EntityFramework.Abstractions;
using PulseAuth.EntityFramework.Entities;
using PulseAuth.Models;

namespace PulseAuth.EntityFramework.Stores;

/// <summary>EF Core-backed <see cref="IConsentStore"/>.</summary>
public class EfConsentStore : IConsentStore
{
    private readonly IPulseAuthDbContext _db;

    /// <summary>Initializes a new instance of the <see cref="EfConsentStore"/> class.</summary>
    public EfConsentStore(IPulseAuthDbContext db) => _db = db ?? throw new ArgumentNullException(nameof(db));

    /// <inheritdoc />
    public async Task<Consent?> GetAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        var e = await _db.Consents.AsNoTracking()
            .FirstOrDefaultAsync(c => c.SubjectId == subjectId && c.ClientId == clientId, ct);
        return e is null ? null : Map(e);
    }

    /// <inheritdoc />
    public async Task StoreAsync(Consent consent, CancellationToken ct = default)
    {
        var scopes = string.Join(" ", consent.Scopes);
        var existing = await _db.Consents
            .FirstOrDefaultAsync(c => c.SubjectId == consent.SubjectId && c.ClientId == consent.ClientId, ct);

        if (existing is null)
        {
            _db.Consents.Add(new ConsentEntity
            {
                SubjectId = consent.SubjectId, ClientId = consent.ClientId, Scopes = scopes,
                CreatedAt = consent.CreatedAt, ExpiresAt = consent.ExpiresAt, Remember = consent.Remember,
            });
        }
        else
        {
            existing.Scopes    = scopes;
            existing.CreatedAt = consent.CreatedAt;
            existing.ExpiresAt = consent.ExpiresAt;
            existing.Remember  = consent.Remember;
        }

        await _db.SaveChangesAsync(ct);
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string subjectId, string clientId, CancellationToken ct = default)
        => await _db.Consents
            .Where(c => c.SubjectId == subjectId && c.ClientId == clientId)
            .ExecuteDeleteAsync(ct);

    /// <inheritdoc />
    public async Task<IReadOnlyList<Consent>> GetBySubjectAsync(string subjectId, CancellationToken ct = default)
        => (await _db.Consents.AsNoTracking().Where(c => c.SubjectId == subjectId).ToListAsync(ct))
            .Select(Map).ToList();

    private static Consent Map(ConsentEntity e) => new()
    {
        SubjectId = e.SubjectId,
        ClientId  = e.ClientId,
        Scopes    = e.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries),
        CreatedAt = e.CreatedAt,
        ExpiresAt = e.ExpiresAt,
        Remember  = e.Remember,
    };
}
