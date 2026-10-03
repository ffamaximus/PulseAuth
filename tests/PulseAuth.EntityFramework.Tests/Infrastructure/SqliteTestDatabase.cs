using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using PulseAuth.Configuration;
using PulseAuth.EntityFramework.DbContexts;
using PulseAuth.EntityFramework.Stores;

namespace PulseAuth.EntityFramework.Tests.Infrastructure;

/// <summary>
/// A throw-away SQLite database for one test, created from the PulseAuth EF model.
/// </summary>
/// <remarks>
/// A temporary file (instead of <c>:memory:</c>) is used so that several DbContexts — each with
/// its own connection, like concurrent HTTP requests in production — can hit the same database
/// at the same time. That is required to test the atomic compare-and-set operations
/// (<c>TryConsumeAsync</c>). The file is deleted when the test ends.
/// </remarks>
public sealed class SqliteTestDatabase : IDisposable
{
    private readonly string _path;
    private readonly DbContextOptions<PulseAuthDbContext> _options;

    public SqliteTestDatabase()
    {
        _path = Path.Combine(Path.GetTempPath(), $"pulseauth-ef-{Guid.NewGuid():N}.db");

        _options = new DbContextOptionsBuilder<PulseAuthDbContext>()
            .UseSqlite($"Data Source={_path};Pooling=False;Default Timeout=30")
            .Options;

        using var ctx = CreateContext();
        ctx.Database.EnsureCreated();
        ctx.Database.ExecuteSqlRaw("PRAGMA journal_mode=WAL;");
    }

    /// <summary>A new context (= a new connection), like a new DI scope / HTTP request.</summary>
    public PulseAuthDbContext CreateContext() => new(_options);

    public static IOptions<PulseAuthOptions> Options(Action<PulseAuthOptions>? configure = null)
    {
        var options = new PulseAuthOptions();
        configure?.Invoke(options);
        return Microsoft.Extensions.Options.Options.Create(options);
    }

    public EfRefreshTokenStore RefreshTokenStore(PulseAuthDbContext ctx, Action<PulseAuthOptions>? configure = null)
        => new(ctx, Options(configure));

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var file in new[] { _path, _path + "-wal", _path + "-shm" })
        {
            try { File.Delete(file); } catch (IOException) { /* best effort */ }
        }
    }
}
