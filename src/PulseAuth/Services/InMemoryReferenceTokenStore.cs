using System.Collections.Concurrent;
using PulseAuth.Abstractions;
using PulseAuth.Helpers;
using PulseAuth.Models;

namespace PulseAuth.Services;

/// <summary>In-memory reference token store (development / single instance).</summary>
public class InMemoryReferenceTokenStore : IReferenceTokenStore
{
    private readonly ConcurrentDictionary<string, ReferenceToken> _tokens = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task StoreAsync(ReferenceToken token, CancellationToken ct = default)
    {
        _tokens[GrantKeyHelper.ToStorageKey(token.Handle)] = Copy(token);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<ReferenceToken?> FindAsync(string handle, CancellationToken ct = default)
        => Task.FromResult(_tokens.TryGetValue(GrantKeyHelper.ToStorageKey(handle), out var t)
            ? Copy(t, handle)
            : null);

    /// <inheritdoc />
    public Task RemoveAsync(string handle, CancellationToken ct = default)
    {
        _tokens.TryRemove(GrantKeyHelper.ToStorageKey(handle), out _);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RemoveBySubjectAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        foreach (var kv in _tokens.Where(kv => kv.Value.SubjectId == subjectId && kv.Value.ClientId == clientId).ToList())
            _tokens.TryRemove(kv.Key, out _);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RemoveExpiredAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _tokens.Where(kv => kv.Value.ExpiresAt < now).ToList())
            _tokens.TryRemove(kv.Key, out _);
        return Task.CompletedTask;
    }

    private static ReferenceToken Copy(ReferenceToken t, string? handle = null) => new()
    {
        Handle = handle ?? t.Handle, ClientId = t.ClientId, SubjectId = t.SubjectId,
        Jwt = t.Jwt, CreatedAt = t.CreatedAt, ExpiresAt = t.ExpiresAt,
    };
}
