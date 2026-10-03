using PulseAuth.Models;

namespace PulseAuth.Abstractions;

/// <summary>Persistence of user consents (one per subject + client).</summary>
public interface IConsentStore
{
    /// <summary>Returns the consent of a user for a client, or null.</summary>
    Task<Consent?> GetAsync(string subjectId, string clientId, CancellationToken ct = default);

    /// <summary>Creates or replaces the consent of a user for a client.</summary>
    Task StoreAsync(Consent consent, CancellationToken ct = default);

    /// <summary>Removes the consent of a user for a client.</summary>
    Task RemoveAsync(string subjectId, string clientId, CancellationToken ct = default);

    /// <summary>Returns all consents of a user (e.g. for a "connected apps" page).</summary>
    Task<IReadOnlyList<Consent>> GetBySubjectAsync(string subjectId, CancellationToken ct = default);
}
