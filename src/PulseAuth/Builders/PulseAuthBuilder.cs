using Microsoft.Extensions.DependencyInjection;
using PulseAuth.Abstractions;
using PulseAuth.Models;
using PulseAuth.Services;

namespace PulseAuth.Builders;

/// <summary>
/// Fluent builder for configuring PulseAuth services.
/// </summary>
public class PulseAuthBuilder
{
    /// <summary>
    /// The service collection to which PulseAuth services are being added.
    /// </summary>
    public IServiceCollection Services { get; }

    /// <summary>
    /// Creates a new instance of <see cref="PulseAuthBuilder"/> with the specified service collection.
    /// </summary>
    /// <param name="services"></param>
    public PulseAuthBuilder(IServiceCollection services)
    {
        Services = services;
    }

    // ── Client Store ──────────────────────────────────────────────────────────

    /// <summary>
    /// Registers an in-memory client store pre-loaded with the provided clients.
    /// Use for development and testing; replace with <see cref="AddClientStore{T}"/> for production.
    /// </summary>
    public PulseAuthBuilder AddInMemoryClients(IEnumerable<Client> clients)
    {
        var list = clients.ToList();
        Services.AddSingleton<IClientStore>(new InMemoryClientStore(list));
        return this;
    }

    /// <summary>
    /// Registers a custom <see cref="IClientStore"/> implementation.
    /// </summary>
    public PulseAuthBuilder AddClientStore<T>() where T : class, IClientStore
    {
        Services.AddScoped<IClientStore, T>();
        return this;
    }

    // ── Key Material ──────────────────────────────────────────────────────────

    /// <summary>
    /// Uses the default in-memory RSA-2048 key pair for token signing.
    /// A new key is generated each time the application restarts.
    /// For production use <see cref="AddKeyMaterialService{T}"/> backed by a persistent key store.
    /// </summary>
    public PulseAuthBuilder AddDeveloperSigningCredential()
    {
        Services.AddSingleton<IKeyMaterialService, RsaKeyMaterialService>();
        return this;
    }

    /// <summary>
    /// Registers a custom <see cref="IKeyMaterialService"/> (e.g., backed by Azure Key Vault).
    /// </summary>
    public PulseAuthBuilder AddKeyMaterialService<T>() where T : class, IKeyMaterialService
    {
        Services.AddSingleton<IKeyMaterialService, T>();
        return this;
    }

    // ── User Authentication ───────────────────────────────────────────────────

    /// <summary>
    /// Registers a custom <see cref="IUserAuthenticationService"/>.
    /// Called automatically when using <c>PulseAuth.Identity</c>.
    /// </summary>
    public PulseAuthBuilder AddUserAuthentication<T>() where T : class, IUserAuthenticationService
    {
        Services.AddScoped<IUserAuthenticationService, T>();
        return this;
    }

    // ── Token Service ─────────────────────────────────────────────────────────

    /// <summary>
    /// Registers a custom <see cref="ITokenService"/>.
    /// </summary>
    public PulseAuthBuilder AddTokenService<T>() where T : class, ITokenService
    {
        Services.AddScoped<ITokenService, T>();
        return this;
    }
}
