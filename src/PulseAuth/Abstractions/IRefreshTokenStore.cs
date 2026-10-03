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

    /// <summary>
    /// Marks the token as consumed / revoked (revocation endpoint, logout).
    /// Built-in stores also set <c>ExpiresAt</c> to now so a revoked token can never fall
    /// inside the rotation reuse grace period.
    /// </summary>
    Task ConsumeAsync(string token, CancellationToken ct = default);

    /// <summary>
    /// Atomically marks the refresh token as consumed <b>only if it has not been consumed yet</b>
    /// (refresh token rotation). Returns <c>true</c> if this call consumed the token, <c>false</c>
    /// if it was already consumed (or does not exist).
    /// </summary>
    /// <param name="token">The refresh token value.</param>
    /// <param name="reuseGracePeriod">
    /// When greater than zero, implementations should set <c>ExpiresAt = UtcNow + reuseGracePeriod</c>
    /// in the same atomic operation. This records when the token was rotated (without a schema
    /// change) so <see cref="Models.RefreshToken.IsWithinReuseGracePeriod"/> can accept a
    /// concurrent request that presents the same token a moment later.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    /// <remarks>
    /// The default implementation is NOT atomic (find + consume), ignores the grace period
    /// (strict one-time use) and exists only for backward compatibility with custom stores.
    /// Override it with a compare-and-set operation
    /// (e.g. <c>UPDATE ... SET IsConsumed = 1, ExpiresAt = @graceUntil WHERE Key = @token AND IsConsumed = 0</c>).
    /// </remarks>
    async Task<bool> TryConsumeAsync(string token, TimeSpan reuseGracePeriod, CancellationToken ct = default)
    {
        var existing = await FindByTokenAsync(token, ct);
        if (existing is null || existing.IsConsumed)
            return false;

        await ConsumeAsync(token, ct);
        return true;
    }

    /// <summary>Revokes all refresh tokens for a given subject + client combination (e.g. on logout).</summary>
    Task RevokeBySubjectAsync(string subjectId, string clientId, CancellationToken ct = default);

    /// <summary>
    /// Called when refresh token <b>reuse</b> is detected (a rotated token presented again
    /// outside the grace period — the classic sign of a stolen token, RFC 9700 §4.14.2).
    /// Revokes every token of the same rotation family (the reused token, its ancestors,
    /// its descendants and any grace-period forks), so both the attacker and the victim
    /// must re-authenticate. Returns the number of tokens revoked (-1 if unknown).
    /// </summary>
    /// <remarks>
    /// Families are linked through <see cref="Models.RefreshToken.PreviousTokenId"/>.
    /// The default implementation cannot walk the chain and falls back to revoking ALL of
    /// the user's tokens for that client via <see cref="RevokeBySubjectAsync"/> (safe, but coarser).
    /// </remarks>
    async Task<int> RevokeFamilyAsync(Models.RefreshToken reusedToken, CancellationToken ct = default)
    {
        await RevokeBySubjectAsync(reusedToken.SubjectId, reusedToken.ClientId, ct);
        return -1;
    }

    /// <summary>Removes all expired tokens. Called periodically for cleanup.</summary>
    Task RemoveExpiredAsync(CancellationToken ct = default);
}
