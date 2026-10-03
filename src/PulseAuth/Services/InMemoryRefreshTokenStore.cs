using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;
using PulseAuth.Helpers;
using PulseAuth.Models;

namespace PulseAuth.Services;

/// <summary>
/// Thread-safe in-memory refresh token store.
/// </summary>
public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly ConcurrentDictionary<string, RefreshToken> _tokens = new();
    private readonly TimeSpan _consumedRetention;

    /// <summary>Initializes a new instance of the <see cref="InMemoryRefreshTokenStore"/> class.</summary>
    public InMemoryRefreshTokenStore(IOptions<PulseAuthOptions>? options = null)
        => _consumedRetention = options?.Value.ConsumedRefreshTokenRetention ?? TimeSpan.FromDays(7);

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
        if (!_tokens.TryGetValue(token, out var rt))
            return Task.FromResult<RefreshToken?>(null);

        // Return a snapshot: callers must never observe (or cause) concurrent mutations.
        lock (rt)
        {
            return Task.FromResult<RefreshToken?>(new RefreshToken
            {
                Token = rt.Token, ClientId = rt.ClientId, SubjectId = rt.SubjectId, Scopes = rt.Scopes.ToArray(),
                CreatedAt = rt.CreatedAt, ExpiresAt = rt.ExpiresAt, IsConsumed = rt.IsConsumed,
                PreviousTokenId = rt.PreviousTokenId,
            });
        }
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
    /// Revokes the whole rotation family of a reused refresh token
    /// (ancestors, descendants and grace-period forks).
    /// </summary>
    public Task<int> RevokeFamilyAsync(RefreshToken reusedToken, CancellationToken ct = default)
    {
        var candidates = _tokens.Values
            .Where(t => t.SubjectId == reusedToken.SubjectId && t.ClientId == reusedToken.ClientId)
            .ToList();

        var family = RefreshTokenFamily.Resolve(
            candidates.Select(t => (t.Token, t.PreviousTokenId)), reusedToken.Token);

        var revoked = 0;
        foreach (var token in candidates.Where(t => family.Contains(t.Token)))
        {
            lock (token)
            {
                if (!token.IsConsumed || token.ExpiresAt > DateTime.UtcNow)
                    revoked++;
                Revoke(token);
            }
        }

        return Task.FromResult(revoked);
    }

    /// <summary>
    /// Removes expired and consumed refresh tokens from the store. This method can be called periodically (e.g., via a background service) to clean up old tokens and free up memory. It checks the ExpiresAt property of each token and removes those that have expired or have been marked as consumed.
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task RemoveExpiredAsync(CancellationToken ct = default)
    {
        // Consumed tokens are kept for ConsumedRefreshTokenRetention so that a replay is
        // still detected as reuse (and revokes the family) instead of looking unknown.
        var now            = DateTime.UtcNow;
        var consumedCutoff = now - _consumedRetention;
        var expired = _tokens.Where(kvp => kvp.Value.IsConsumed
                                               ? kvp.Value.ExpiresAt < consumedCutoff
                                               : kvp.Value.ExpiresAt < now)
                             .Select(kvp => kvp.Key)
                             .ToList();

        foreach (var key in expired)
            _tokens.TryRemove(key, out _);

        return Task.CompletedTask;
    }
}
