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

    /// <summary>Removes all expired codes. Called periodically for cleanup.</summary>
    Task RemoveExpiredAsync(CancellationToken ct = default);
}
