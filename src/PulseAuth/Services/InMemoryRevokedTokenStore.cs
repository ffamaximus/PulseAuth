using System.Collections.Concurrent;
using PulseAuth.Abstractions;

namespace PulseAuth.Services;

/// <summary>In-memory <see cref="IRevokedTokenStore"/> (single instance / development).</summary>
public class InMemoryRevokedTokenStore : IRevokedTokenStore
{
    private readonly ConcurrentDictionary<string, DateTime> _revoked = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task RevokeAsync(string tokenId, DateTime expiresAt, CancellationToken ct = default)
    {
        _revoked.AddOrUpdate(tokenId, expiresAt, (_, existing) => existing > expiresAt ? existing : expiresAt);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> IsRevokedAsync(string tokenId, CancellationToken ct = default)
        => Task.FromResult(_revoked.TryGetValue(tokenId, out var until) && until > DateTime.UtcNow);

    /// <inheritdoc />
    public Task RemoveExpiredAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _revoked.Where(kv => kv.Value <= now).ToList())
            _revoked.TryRemove(kv);
        return Task.CompletedTask;
    }
}
