using System.Collections.Concurrent;
using PulseAuth.Abstractions;
using PulseAuth.Models;

namespace PulseAuth.Services;

/// <summary>In-memory consent store (development / single instance).</summary>
public class InMemoryConsentStore : IConsentStore
{
    private readonly ConcurrentDictionary<(string Subject, string Client), Consent> _consents = new();

    /// <inheritdoc />
    public Task<Consent?> GetAsync(string subjectId, string clientId, CancellationToken ct = default)
        => Task.FromResult(_consents.TryGetValue((subjectId, clientId), out var c) ? Copy(c) : null);

    /// <inheritdoc />
    public Task StoreAsync(Consent consent, CancellationToken ct = default)
    {
        _consents[(consent.SubjectId, consent.ClientId)] = Copy(consent);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RemoveAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        _consents.TryRemove((subjectId, clientId), out _);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<Consent>> GetBySubjectAsync(string subjectId, CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<Consent>>(
            _consents.Values.Where(c => c.SubjectId == subjectId).Select(Copy).ToList());

    private static Consent Copy(Consent c) => new()
    {
        SubjectId = c.SubjectId, ClientId = c.ClientId, Scopes = c.Scopes.ToArray(),
        CreatedAt = c.CreatedAt, ExpiresAt = c.ExpiresAt, Remember = c.Remember,
    };
}
