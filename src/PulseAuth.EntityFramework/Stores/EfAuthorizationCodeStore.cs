using Microsoft.EntityFrameworkCore;
using PulseAuth.Abstractions;
using PulseAuth.EntityFramework.DbContext;
using PulseAuth.EntityFramework.Entities;
using PulseAuth.Models;

namespace PulseAuth.EntityFramework.Stores;

public class EfAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly PulseAuthDbContext _db;

    public EfAuthorizationCodeStore(PulseAuthDbContext db) => _db = db;

    public async Task StoreAsync(AuthorizationCode code, CancellationToken ct = default)
    {
        _db.AuthorizationCodes.Add(new AuthorizationCodeEntity
        {
            Key                 = code.Code,
            ClientId            = code.ClientId,
            SubjectId           = code.SubjectId,
            Scopes              = string.Join(" ", code.Scopes),
            CodeChallenge       = code.CodeChallenge,
            CodeChallengeMethod = code.CodeChallengeMethod,
            RedirectUri         = code.RedirectUri,
            Nonce               = code.Nonce,
            SessionId           = code.SessionId,
            CreatedAt           = code.CreatedAt,
            ExpiresAt           = code.ExpiresAt,
        });
        await _db.SaveChangesAsync(ct);
    }

    public async Task<AuthorizationCode?> FindByCodeAsync(string code, CancellationToken ct = default)
    {
        var e = await _db.AuthorizationCodes
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Key == code, ct);

        if (e is null) return null;

        return new AuthorizationCode
        {
            Code                = e.Key,
            ClientId            = e.ClientId,
            SubjectId           = e.SubjectId,
            Scopes              = e.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            CodeChallenge       = e.CodeChallenge,
            CodeChallengeMethod = e.CodeChallengeMethod,
            RedirectUri         = e.RedirectUri,
            Nonce               = e.Nonce,
            SessionId           = e.SessionId,
            CreatedAt           = e.CreatedAt,
            ExpiresAt           = e.ExpiresAt,
            IsConsumed          = e.IsConsumed,
        };
    }

    public async Task ConsumeAsync(string code, CancellationToken ct = default)
    {
        await _db.AuthorizationCodes
            .Where(c => c.Key == code)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.IsConsumed, true), ct);
    }

    public async Task RemoveExpiredAsync(CancellationToken ct = default)
    {
        var cutoff = DateTime.UtcNow;
        await _db.AuthorizationCodes
            .Where(c => c.ExpiresAt < cutoff || c.IsConsumed)
            .ExecuteDeleteAsync(ct);
    }
}
