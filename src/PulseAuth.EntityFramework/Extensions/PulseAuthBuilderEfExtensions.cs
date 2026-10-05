using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PulseAuth.Abstractions;
using PulseAuth.Builders;
using PulseAuth.EntityFramework.Abstractions;
using PulseAuth.EntityFramework.DbContexts;
using PulseAuth.EntityFramework.Stores;

namespace PulseAuth.EntityFramework.Extensions;

/// <summary>
/// Extension methods to wire up EF Core-backed PulseAuth stores.
/// </summary>
public static class PulseAuthBuilderEfExtensions
{
    // ── Standalone PulseAuthDbContext ─────────────────────────────────────────

    /// <summary>
    /// Registers <see cref="PulseAuthDbContext"/> (provider-agnostic) and replaces the
    /// in-memory stores with EF Core-backed implementations.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddPulseAuth(...)
    ///     .AddEntityFrameworkStores(opts => opts.UseMySql(cs, version));
    /// </code>
    /// </example>
    public static PulseAuthBuilder AddEntityFrameworkStores(
        this PulseAuthBuilder builder,
        Action<DbContextOptionsBuilder> optionsAction)
    {
        builder.Services.AddDbContext<PulseAuthDbContext>(optionsAction);
        builder.Services.AddScoped<IPulseAuthDbContext>(
            sp => sp.GetRequiredService<PulseAuthDbContext>());
        RegisterStores(builder);
        return builder;
    }

    /// <summary>
    /// Registers EF Core stores against a <see cref="PulseAuthDbContext"/> that is
    /// already registered in the DI container.
    /// </summary>
    public static PulseAuthBuilder AddEntityFrameworkStores(this PulseAuthBuilder builder)
    {
        builder.Services.AddScoped<IPulseAuthDbContext>(
            sp => sp.GetRequiredService<PulseAuthDbContext>());
        RegisterStores(builder);
        return builder;
    }

    // ── Derived from PulseAuthDbContext (e.g. AppDbContext : PulseAuthDbContext) ──

    /// <summary>
    /// Registers a derived <see cref="PulseAuthDbContext"/> and replaces the in-memory stores
    /// with EF Core-backed implementations. Use this when your <c>DbContext</c> inherits
    /// <see cref="PulseAuthDbContext"/> to share a single database schema.
    /// </summary>
    /// <typeparam name="TContext">Your derived context type.</typeparam>
    /// <example>
    /// <code>
    /// public class AppDbContext : PulseAuthDbContext
    /// {
    ///     public AppDbContext(DbContextOptions&lt;AppDbContext&gt; options) : base(options) { }
    /// }
    ///
    /// builder.Services.AddPulseAuth(...)
    ///     .AddEntityFrameworkStores&lt;AppDbContext&gt;(opts => opts.UseMySql(...));
    /// </code>
    /// </example>
    public static PulseAuthBuilder AddEntityFrameworkStores<TContext>(
        this PulseAuthBuilder builder,
        Action<DbContextOptionsBuilder> optionsAction)
        where TContext : PulseAuthDbContext
    {
        builder.Services.AddDbContext<TContext>(optionsAction);
        builder.Services.AddScoped<IPulseAuthDbContext>(
            sp => sp.GetRequiredService<TContext>());
        RegisterStores(builder);
        return builder;
    }

    /// <summary>
    /// Registers EF Core stores against a derived <see cref="PulseAuthDbContext"/> that is
    /// already registered in the DI container.
    /// </summary>
    public static PulseAuthBuilder AddEntityFrameworkStores<TContext>(this PulseAuthBuilder builder)
        where TContext : PulseAuthDbContext
    {
        builder.Services.AddScoped<IPulseAuthDbContext>(
            sp => sp.GetRequiredService<TContext>());
        RegisterStores(builder);
        return builder;
    }

    // ── PulseAuthIdentityDbContext<TUser> (combined Identity + PulseAuth) ─────

    /// <summary>
    /// Registers EF Core stores against a context that inherits
    /// <see cref="PulseAuthIdentityDbContext{TUser}"/> (ASP.NET Core Identity +
    /// PulseAuth tables in a single migration). The context must already be registered
    /// in the DI container via <c>AddIdentity().AddEntityFrameworkStores&lt;TContext&gt;()</c>.
    /// </summary>
    /// <typeparam name="TContext">
    /// Your context type (must implement <see cref="IPulseAuthDbContext"/> and
    /// inherit <see cref="DbContext"/>).
    /// </typeparam>
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddIdentity&lt;IdentityUser, IdentityRole&gt;()
    ///     .AddEntityFrameworkStores&lt;AuthDbContext&gt;();
    ///
    /// builder.Services.AddPulseAuth(...)
    ///     .AddEntityFrameworkStoresWithIdentity&lt;AuthDbContext&gt;();
    /// </code>
    /// </example>
    public static PulseAuthBuilder AddEntityFrameworkStoresWithIdentity<TContext>(
        this PulseAuthBuilder builder)
        where TContext : DbContext, IPulseAuthDbContext
    {
        builder.Services.AddScoped<IPulseAuthDbContext>(
            sp => sp.GetRequiredService<TContext>());
        RegisterStores(builder);
        return builder;
    }

    // ── Shared helper ─────────────────────────────────────────────────────────

    private static void RegisterStores(PulseAuthBuilder builder)
    {
        builder.Services.AddScoped<IClientStore,            EfClientStore>();
        builder.Services.AddScoped<IAuthorizationCodeStore, EfAuthorizationCodeStore>();
        builder.Services.AddScoped<IRefreshTokenStore,      EfRefreshTokenStore>();
        builder.Services.AddScoped<IReferenceTokenStore,    EfReferenceTokenStore>();
        builder.Services.AddScoped<IConsentStore,           EfConsentStore>();
        builder.Services.AddScoped<IRevokedTokenStore,      EfRevokedTokenStore>();
        builder.Services.AddMemoryCache(); // CORS origin cache (EfClientStore)
    }
}
