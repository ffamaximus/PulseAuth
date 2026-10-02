using PulseAuth.Models;

namespace PulseAuth.Abstractions;

/// <summary>
/// Manages authorization code persistence (Authorization Code flow).
/// </summary>
public interface IAuthorizationCodeStore
{
    /// <summary>Persists a new authorization code.</summary>
    Task StoreAsync(AuthorizationCode code, CancellationToken ct = default);

    /// <summary>Retrieves a code by its value. Returns null if not found or already consumed.</summary>
    Task<AuthorizationCode?> FindByCodeAsync(string code, CancellationToken ct = default);

    /// <summary>Marks the code as consumed so it cannot be reused.</summary>
    Task ConsumeAsync(string code, CancellationToken ct = default);

    /// <summary>
    /// Atomically marks the code as consumed <b>only if it has not been consumed yet</b>.
    /// Returns <c>true</c> if this call consumed the code, <c>false</c> if it was already
    /// consumed (or does not exist). The token endpoint calls this <i>before</i> issuing
    /// tokens, so two concurrent requests with the same code can never both succeed.
    /// </summary>
    /// <remarks>
    /// The default implementation is NOT atomic (find + consume) and exists only for
    /// backward compatibility with custom stores. Override it with a compare-and-set
    /// operation (e.g. <c>UPDATE ... WHERE Key = @code AND IsConsumed = 0</c>).
    /// </remarks>
    async Task<bool> TryConsumeAsync(string code, CancellationToken ct = default)
    {
        var existing = await FindByCodeAsync(code, ct);
        if (existing is null || existing.IsConsumed)
            return false;

        await ConsumeAsync(code, ct);
        return true;
    }

    /// <summary>Removes all expired codes. Called periodically for cleanup.</summary>
    Task RemoveExpiredAsync(CancellationToken ct = default);
}
