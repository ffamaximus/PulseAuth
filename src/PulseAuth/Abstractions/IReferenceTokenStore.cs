using PulseAuth.Models;

namespace PulseAuth.Abstractions;

/// <summary>Persistence of reference (opaque) access tokens.</summary>
public interface IReferenceTokenStore
{
    /// <summary>Persists a reference token. Implementations should store only a hash of the handle.</summary>
    Task StoreAsync(ReferenceToken token, CancellationToken ct = default);

    /// <summary>Finds a token by handle (returns expired tokens too; callers check expiry).</summary>
    Task<ReferenceToken?> FindAsync(string handle, CancellationToken ct = default);

    /// <summary>Removes (revokes) a token.</summary>
    Task RemoveAsync(string handle, CancellationToken ct = default);

    /// <summary>Removes all tokens of a subject for a client (logout, user blocked, password change).</summary>
    Task RemoveBySubjectAsync(string subjectId, string clientId, CancellationToken ct = default);

    /// <summary>Removes expired tokens (called by the cleanup job).</summary>
    Task RemoveExpiredAsync(CancellationToken ct = default);
}
