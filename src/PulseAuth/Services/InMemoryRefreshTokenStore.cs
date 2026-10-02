using System.Collections.Concurrent;
using PulseAuth.Abstractions;
using PulseAuth.Models;

namespace PulseAuth.Services;

/// <summary>
/// Thread-safe in-memory refresh token store.
/// </summary>
public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly ConcurrentDictionary<string, RefreshToken> _tokens = new();

    /// <summary>
    /// Stores a new refresh token in memory. This implementation is thread-safe and suitable for testing or development environments.
    /// </summary>
    /// <param name="token"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task StoreAsync(RefreshToken token, CancellationToken ct = default)
    {
        _tokens[token.Token] = token;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Retrieves a refresh token by its token string. Returns null if the token does not exist or has been consumed/expired.
    /// </summary>
    /// <param name="token"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task<RefreshToken?> FindByTokenAsync(string token, CancellationToken ct = default)
    {
        _tokens.TryGetValue(token, out var rt);
        return Task.FromResult(rt);
    }

    /// <summary>
    /// Marks a refresh token as consumed. This method does not remove the token from the store, but sets its IsConsumed flag to true.
    /// </summary>
    /// <param name="token"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task ConsumeAsync(string token, CancellationToken ct = default)
    {
        if (_tokens.TryGetValue(token, out var rt))
        {
            lock (rt)
                Revoke(rt);
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Atomically consumes the token. Returns <c>true</c> only for the first caller;
    /// any concurrent or later call with the same value returns <c>false</c>.
    /// </summary>
    public Task<bool> TryConsumeAsync(string token, TimeSpan reuseGracePeriod, CancellationToken ct = default)
    {
        if (!_tokens.TryGetValue(token, out var rt))
            return Task.FromResult(false);

        lock (rt)
        {
            if (rt.IsConsumed)
                return Task.FromResult(false);

            rt.IsConsumed = true;
            if (reuseGracePeriod > TimeSpan.Zero)
                rt.ExpiresAt = DateTime.UtcNow.Add(reuseGracePeriod);
            return Task.FromResult(true);
        }
    }

    private static void Revoke(RefreshToken rt)
    {
        rt.IsConsumed = true;
        var now = DateTime.UtcNow;
        if (rt.ExpiresAt > now)
            rt.ExpiresAt = now; // never inside the reuse grace window
    }

    /// <summary>
    /// Revokes all refresh tokens for a given subject ID and client ID. This method marks the tokens as consumed, which prevents them from being used to obtain new access tokens. This is useful for scenarios like user logout or account compromise, where you want to invalidate all existing refresh tokens for a user and client combination.
    /// </summary>
    /// <param name="subjectId"></param>
    /// <param name="clientId"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task RevokeBySubjectAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        var toRevoke = _tokens.Values
            .Where(t => t.SubjectId == subjectId && t.ClientId == clientId)
            .ToList();

        foreach (var token in toRevoke)
        {
            lock (token)
                Revoke(token);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Removes expired and consumed refresh tokens from the store. This method can be called periodically (e.g., via a background service) to clean up old tokens and free up memory. It checks the ExpiresAt property of each token and removes those that have expired or have been marked as consumed.
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task RemoveExpiredAsync(CancellationToken ct = default)
    {
        var now     = DateTime.UtcNow;
        var expired = _tokens.Where(kvp => kvp.Value.ExpiresAt < now || kvp.Value.IsConsumed)
                             .Select(kvp => kvp.Key)
                             .ToList();

        foreach (var key in expired)
            _tokens.TryRemove(key, out _);

        return Task.CompletedTask;
    }
}
