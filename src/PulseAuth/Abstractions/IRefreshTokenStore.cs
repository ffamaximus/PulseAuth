using PulseAuth.Models;

namespace PulseAuth.Abstractions;

/// <summary>
/// Manages refresh token persistence.
/// </summary>
public interface IRefreshTokenStore
{
    /// <summary>Persists a new refresh token.</summary>
    Task StoreAsync(RefreshToken token, CancellationToken ct = default);

    /// <summary>Retrieves a refresh token by its value. Returns null if not found.</summary>
    Task<RefreshToken?> FindByTokenAsync(string token, CancellationToken ct = default);

    /// <summary>Marks the token as consumed (rotation — one-time use).</summary>
    Task ConsumeAsync(string token, CancellationToken ct = default);

    /// <summary>Revokes all refresh tokens for a given subject + client combination (e.g. on logout).</summary>
    Task RevokeBySubjectAsync(string subjectId, string clientId, CancellationToken ct = default);

    /// <summary>Removes all expired tokens. Called periodically for cleanup.</summary>
    Task RemoveExpiredAsync(CancellationToken ct = default);
}
