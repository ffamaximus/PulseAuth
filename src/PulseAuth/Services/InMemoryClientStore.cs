using PulseAuth.Abstractions;
using PulseAuth.Models;

namespace PulseAuth.Services;

/// <summary>
/// In-memory client store. Suitable for development and testing.
/// For production use <c>PulseAuth.EntityFramework</c> or provide your own <see cref="IClientStore"/>.
/// </summary>
public class InMemoryClientStore : IClientStore
{
    private readonly IReadOnlyDictionary<string, Client> _clients;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryClientStore"/> class with the provided list of clients. The clients are stored in a dictionary for fast lookup by client_id. This constructor is typically used in development and testing scenarios where a fixed set of clients is sufficient. For production use, consider implementing a more robust client store that retrieves client information from a database or other persistent storage. The clients parameter should contain all the necessary information about each client (e.g., allowed grant types, redirect URIs, allowed scopes) that will be used during the authorization process to validate incoming requests.
    /// </summary>
    /// <param name="clients"></param>
    public InMemoryClientStore(IEnumerable<Client> clients)
    {
        _clients = clients.ToDictionary(c => c.ClientId, StringComparer.Ordinal);
    }

    /// <summary>
    /// Finds a client by its client_id. This method is used during the authorization process to retrieve the client's configuration and validate incoming requests. The method looks up the client in the in-memory dictionary using the provided clientId. If a client with the specified clientId exists, it returns the corresponding Client object; otherwise, it returns null. The cancellation token can be used to cancel the operation if needed, although in this in-memory implementation, it is not utilized since the lookup is fast and does not involve any asynchronous operations.
    /// </summary>
    /// <param name="clientId"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    public Task<Client?> FindClientByIdAsync(string clientId, CancellationToken ct = default)
    {
        _clients.TryGetValue(clientId, out var client);
        return Task.FromResult(client);
    }

    /// <summary>
    /// Returns true if any enabled client lists the origin in <see cref="Client.AllowedCorsOrigins"/>.
    /// </summary>
    public Task<bool> IsOriginAllowedAsync(string origin, CancellationToken ct = default)
        => Task.FromResult(_clients.Values.Any(c =>
            c.Enabled &&
            c.AllowedCorsOrigins.Any(o => string.Equals(o.TrimEnd('/'), origin.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))));
}
