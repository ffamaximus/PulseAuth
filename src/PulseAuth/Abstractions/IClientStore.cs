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

    /// <summary>
    /// Returns true if any enabled client lists <paramref name="origin"/> (e.g. <c>https://app.example.com</c>)
    /// in <see cref="Client.AllowedCorsOrigins"/>. Used to answer browser CORS requests to the
    /// token, userinfo and revocation endpoints. The default implementation allows no origin.
    /// </summary>
    Task<bool> IsOriginAllowedAsync(string origin, CancellationToken ct = default)
        => Task.FromResult(false);
}
