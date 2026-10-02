using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using PulseAuth.Abstractions;
using PulseAuth.Models;
using PulseAuth.Services;

namespace PulseAuth.Builders;

/// <summary>
/// Fluent builder for configuring PulseAuth services.
/// </summary>
public class PulseAuthBuilder
{
    // Extra validation keys registered via AddValidationKey (key rotation).
    // Read lazily when IKeyMaterialService is first resolved, so call order does not matter.
    private readonly List<SecurityKey> _validationKeys = [];

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
    /// Uses a developer RSA-2048 key for token signing (development / testing only).
    /// </summary>
    /// <param name="persistKey">
    /// <c>true</c> (default): the key is created once and persisted as a PEM file, so tokens
    /// survive restarts and instances sharing the file use the same key.
    /// <c>false</c>: an in-memory key is generated on every start.
    /// </param>
    /// <param name="filename">
    /// Path of the key file. Defaults to <c>pulseauth-tempkey.pem</c> in the current directory.
    /// Keep this file out of source control.
    /// </param>
    /// <remarks>
    /// For production use <see cref="AddSigningCredential(X509Certificate2, string?)"/> /
    /// <see cref="AddSigningCredential(SecurityKey, string?)"/> or a custom
    /// <see cref="AddKeyMaterialService{T}"/> backed by Key Vault / KMS.
    /// </remarks>
    public PulseAuthBuilder AddDeveloperSigningCredential(bool persistKey = true, string? filename = null)
    {
        var path = persistKey
            ? filename ?? Path.Combine(Directory.GetCurrentDirectory(), RsaKeyMaterialService.DefaultKeyFileName)
            : null;

        Services.AddSingleton<IKeyMaterialService>(sp =>
            new RsaKeyMaterialService(path, sp.GetService<ILogger<RsaKeyMaterialService>>()));
        return this;
    }

    /// <summary>
    /// Signs tokens with the given credentials (production). Every instance of the
    /// authorization server must be configured with the same key.
    /// </summary>
    public PulseAuthBuilder AddSigningCredential(SigningCredentials credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        Services.AddSingleton<IKeyMaterialService>(_ =>
            new StaticKeyMaterialService(credentials, _validationKeys));
        return this;
    }

    /// <summary>
    /// Signs tokens with an RSA or ECDSA key (e.g. loaded from Azure Key Vault / AWS KMS export / PEM).
    /// </summary>
    /// <param name="key">Private RSA or ECDSA key.</param>
    /// <param name="algorithm">JWS algorithm. Defaults to RS256 for RSA and ES256/384/512 for ECDSA.</param>
    public PulseAuthBuilder AddSigningCredential(SecurityKey key, string? algorithm = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        return AddSigningCredential(new SigningCredentials(key, algorithm ?? KeyMaterialHelper.DefaultAlgorithm(key)));
    }

    /// <summary>
    /// Signs tokens with an X.509 certificate that includes its private key (RSA or ECDSA).
    /// The <c>kid</c> published in the JWKS is the certificate thumbprint.
    /// </summary>
    public PulseAuthBuilder AddSigningCredential(X509Certificate2 certificate, string? algorithm = null)
        => AddSigningCredential(KeyMaterialHelper.FromCertificate(certificate, requirePrivateKey: true), algorithm);

    /// <summary>
    /// Publishes an additional public key in the JWKS and accepts it when validating tokens,
    /// without using it for signing. Use during key rotation for the previous (or next) key.
    /// Only applies to keys configured with <c>AddSigningCredential(...)</c>.
    /// </summary>
    public PulseAuthBuilder AddValidationKey(SecurityKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _validationKeys.Add(key);
        return this;
    }

    /// <summary>
    /// Publishes an additional certificate's public key for validation (key rotation).
    /// The certificate does not need a private key.
    /// </summary>
    public PulseAuthBuilder AddValidationKey(X509Certificate2 certificate)
        => AddValidationKey(KeyMaterialHelper.FromCertificate(certificate, requirePrivateKey: false));

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
