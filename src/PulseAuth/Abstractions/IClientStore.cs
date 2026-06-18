using PulseAuth.Models;

namespace PulseAuth.Abstractions;

/// <summary>
/// Retrieves registered OAuth2 clients.
/// Implement this interface to use a custom persistence store.
/// </summary>
public interface IClientStore
{
    /// <summary>Finds a client by its client_id. Returns null if not found.</summary>
    Task<Client?> FindClientByIdAsync(string clientId, CancellationToken ct = default);
}
