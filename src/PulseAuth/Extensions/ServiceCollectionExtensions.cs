using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PulseAuth.Abstractions;
using PulseAuth.Builders;
using PulseAuth.Configuration;
using PulseAuth.Services;
using PulseAuth.Validators;

namespace PulseAuth.Extensions;

/// <summary>
/// Extension methods for registering PulseAuth services in the DI container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds PulseAuth authorization server services to the DI container.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Action to configure <see cref="PulseAuthOptions"/>.</param>
    /// <returns>A <see cref="PulseAuthBuilder"/> for further configuration.</returns>
    /// <example>
    /// <code>
    /// builder.Services.AddPulseAuth(options =>
    /// {
    ///     options.Issuer = "https://auth.myapp.com";
    /// })
    /// .AddDeveloperSigningCredential()
    /// .AddInMemoryClients(Config.Clients)
    /// .AddIdentityUsers&lt;ApplicationUser&gt;();
    /// </code>
    /// </example>
    public static PulseAuthBuilder AddPulseAuth(
        this IServiceCollection services,
        Action<PulseAuthOptions>? configure = null)
    {
        // Options
        var optionsBuilder = services.AddOptions<PulseAuthOptions>();
        if (configure is not null)
            optionsBuilder.Configure(configure);

        // Core validators
        services.AddScoped<AuthorizeRequestValidator>();
        services.AddScoped<TokenRequestValidator>();

        // Default stores (in-memory — overridable)
        services.TryAddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
        services.TryAddSingleton<IRefreshTokenStore,      InMemoryRefreshTokenStore>();
        services.TryAddSingleton<IReferenceTokenStore,    InMemoryReferenceTokenStore>();
        services.TryAddSingleton<IConsentStore,           InMemoryConsentStore>();

        // Access token validation (userinfo, introspection) and consent page API
        services.TryAddScoped<AccessTokenValidator>();
        services.TryAddScoped<IConsentInteractionService, ConsentInteractionService>();

        // Default token service
        services.TryAddScoped<ITokenService, DefaultTokenService>();

        // Periodic removal of expired codes / refresh tokens (PulseAuthOptions.EnableTokenCleanup)
        services.AddHostedService<TokenCleanupService>();

        // HttpContext accessor (needed for endpoints)
        services.AddHttpContextAccessor();

        // HTTP client factory (used by social token validators e.g. Facebook Graph API)
        services.AddHttpClient();

        return new PulseAuthBuilder(services);
    }
}
