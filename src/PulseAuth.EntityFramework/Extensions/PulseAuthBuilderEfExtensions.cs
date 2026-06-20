using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PulseAuth.Abstractions;
using PulseAuth.Builders;
using PulseAuth.EntityFramework.DbContexts;
using PulseAuth.EntityFramework.Stores;

namespace PulseAuth.EntityFramework.Extensions;

/// <summary>
/// Extension methods to use EF Core-backed stores with PulseAuth.
/// </summary>
public static class PulseAuthBuilderEfExtensions
{
    // ── Standalone PulseAuthDbContext ─────────────────────────────────────────

    /// <summary>
    /// Registers <see cref="PulseAuthDbContext"/> and replaces the in-memory stores with
    /// EF Core-backed implementations.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddPulseAuth(...)
    ///     .AddEntityFrameworkStores(opts => opts.UseSqlServer(connectionString));
    /// </code>
    /// </example>
    public static PulseAuthBuilder AddEntityFrameworkStores(
        this PulseAuthBuilder builder,
        Action<DbContextOptionsBuilder> optionsAction)
    {
        builder.Services.AddDbContext<PulseAuthDbContext>(optionsAction);
        RegisterStores(builder);
        return builder;
    }

    /// <summary>
    /// Registers EF Core stores against a <see cref="PulseAuthDbContext"/> that is
    /// already registered in the DI container.
    /// </summary>
    public static PulseAuthBuilder AddEntityFrameworkStores(this PulseAuthBuilder builder)
    {
        RegisterStores(builder);
        return builder;
    }

    // ── Derived context (your AppDbContext : PulseAuthDbContext) ──────────────

    /// <summary>
    /// Registers a derived context and replaces the in-memory stores with EF Core-backed
    /// implementations. Use this when your application's <c>DbContext</c> inherits
    /// <see cref="PulseAuthDbContext"/> to share a single database schema.
    /// </summary>
    /// <typeparam name="TContext">Your derived context type.</typeparam>
    /// <example>
    /// <code>
    /// // AppDbContext.cs
    /// public class AppDbContext : PulseAuthDbContext
    /// {
    ///     public AppDbContext(DbContextOptions&lt;AppDbContext&gt; options) : base(options) { }
    ///     public DbSet&lt;Order&gt; Orders { get; set; } = default!;
    /// }
    ///
    /// // Program.cs
    /// builder.Services.AddPulseAuth(...)
    ///     .AddEntityFrameworkStores&lt;AppDbContext&gt;(opts =>
    ///         opts.UseMySQL(connectionString));
    /// </code>
    /// </example>
    public static PulseAuthBuilder AddEntityFrameworkStores<TContext>(
        this PulseAuthBuilder builder,
        Action<DbContextOptionsBuilder> optionsAction)
        where TContext : PulseAuthDbContext
    {
        builder.Services.AddDbContext<TContext>(optionsAction);

        // Expose TContext as PulseAuthDbContext so the EF stores can resolve it from DI.
        builder.Services.AddScoped<PulseAuthDbContext>(
            sp => sp.GetRequiredService<TContext>());

        RegisterStores(builder);
        return builder;
    }

    /// <summary>
    /// Registers EF Core stores against a derived context that is already registered
    /// in the DI container.
    /// </summary>
    /// <typeparam name="TContext">Your derived context type.</typeparam>
    public static PulseAuthBuilder AddEntityFrameworkStores<TContext>(this PulseAuthBuilder builder)
        where TContext : PulseAuthDbContext
    {
        builder.Services.AddScoped<PulseAuthDbContext>(
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
    }
}
