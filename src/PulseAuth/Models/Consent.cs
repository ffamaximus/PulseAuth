namespace PulseAuth.Models;

/// <summary>Scopes a user has allowed a client to access.</summary>
public class Consent
{
    /// <summary>User id.</summary>
    public string SubjectId { get; set; } = default!;

    /// <summary>Client id.</summary>
    public string ClientId { get; set; } = default!;

    /// <summary>Granted scopes.</summary>
    public IReadOnlyCollection<string> Scopes { get; set; } = [];

    /// <summary>When the consent was given (UTC).</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Expiration (UTC); <c>null</c> = until revoked.</summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// False for a one-time consent ("allow this time only"): it is consumed by the next
    /// authorization request.
    /// </summary>
    public bool Remember { get; set; } = true;

    /// <summary>True if the consent is still valid at <paramref name="utcNow"/>.</summary>
    public bool IsValid(DateTime utcNow) => ExpiresAt is null || ExpiresAt > utcNow;

    /// <summary>True if every requested scope is covered by this consent.</summary>
    public bool Covers(IEnumerable<string> requestedScopes)
        => requestedScopes.All(s => Scopes.Contains(s, StringComparer.Ordinal));
}
