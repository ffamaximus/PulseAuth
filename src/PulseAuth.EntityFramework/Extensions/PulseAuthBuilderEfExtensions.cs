using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PulseAuth.Abstractions;
using PulseAuth.Builders;
using PulseAuth.EntityFramework.DbContext;
using PulseAuth.EntityFramework.Stores;

namespace PulseAuth.EntityFramework.Extensions;

/// <summary>
/// Extension methods to use EF Core-backed stores with PulseAuth.
/// </summary>
public static class PulseAuthBuilderEfExtensions
{
    /// <summary>
    /// Replaces the in-memory stores with EF Core-backed stores using <see cref="PulseAuthDbContext"/>.
    /// </summary>
    /// <param name="builder">The PulseAuth builder.</param>
    /// <param name="optionsAction">EF Core DbContext options (connection string, provider).</param>
    /// <example>
    /// <code>
    /// services.AddPulseAuth(...)
    ///     .AddEntityFrameworkStores(opts =>
    ///         opts.UseSqlServer(connectionString));
    /// </code>
    /// </example>
    public static PulseAuthBuilder AddEntityFrameworkStores(
        this PulseAuthBuilder builder,
        Action<DbContextOptionsBuilder> optionsAction)
    {
        builder.Services.AddDbContext<PulseAuthDbContext>(optionsAction);

        // Override the in-memory stores registered by AddPulseAuth()
        builder.Services.AddScoped<IClientStore,            EfClientStore>();
        builder.Services.AddScoped<IAuthorizationCodeStore, EfAuthorizationCodeStore>();
        builder.Services.AddScoped<IRefreshTokenStore,      EfRefreshTokenStore>();

        return builder;
    }

    /// <summary>
    /// Registers the EF Core stores against an existing <see cref="PulseAuthDbContext"/>
    /// that is already registered in the container.
    /// </summary>
    public static PulseAuthBuilder AddEntityFrameworkStores(this PulseAuthBuilder builder)
    {
        builder.Services.AddScoped<IClientStore,            EfClientStore>();
        builder.Services.AddScoped<IAuthorizationCodeStore, EfAuthorizationCodeStore>();
        builder.Services.AddScoped<IRefreshTokenStore,      EfRefreshTokenStore>();

        return builder;
    }
}
