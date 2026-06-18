using System.Collections.Concurrent;
using PulseAuth.Abstractions;
using PulseAuth.Models;

namespace PulseAuth.Services;

/// <summary>
/// Thread-safe in-memory authorization code store.
/// Suitable for single-instance deployments and development.
/// </summary>
public class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly ConcurrentDictionary<string, AuthorizationCode> _codes = new();

    /// <summary>
    /// Stores an authorization code in memory. The code will be available until it expires or is consumed.
    /// </summary>
    /// <param name="code"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task StoreAsync(AuthorizationCode code, CancellationToken ct = default)
    {
        _codes[code.Code] = code;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Finds an authorization code by its code string. Returns null if not found, expired, or consumed.
    /// </summary>
    /// <param name="code"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task<AuthorizationCode?> FindByCodeAsync(string code, CancellationToken ct = default)
    {
        _codes.TryGetValue(code, out var authCode);
        return Task.FromResult(authCode);
    }

    /// <summary>
    /// Marks an authorization code as consumed. This prevents it from being used again. The code will still exist in memory until it expires or is removed by cleanup.
    /// </summary>
    /// <param name="code"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task ConsumeAsync(string code, CancellationToken ct = default)
    {
        if (_codes.TryGetValue(code, out var authCode))
            authCode.IsConsumed = true;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Removes expired and consumed authorization codes from the store. This method should be called periodically (e.g., via a background timer) to clean up old codes and prevent memory bloat. Codes that have expired or have been marked as consumed will be removed from the in-memory store.
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task RemoveExpiredAsync(CancellationToken ct = default)
    {
        var now     = DateTime.UtcNow;
        var expired = _codes.Where(kvp => kvp.Value.ExpiresAt < now || kvp.Value.IsConsumed)
                            .Select(kvp => kvp.Key)
                            .ToList();

        foreach (var key in expired)
            _codes.TryRemove(key, out _);

        return Task.CompletedTask;
    }
}
