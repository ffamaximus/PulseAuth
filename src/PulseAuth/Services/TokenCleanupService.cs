using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PulseAuth.Abstractions;
using PulseAuth.Configuration;

namespace PulseAuth.Services;

/// <summary>
/// Background job that periodically removes expired authorization codes and refresh tokens
/// (<see cref="IAuthorizationCodeStore.RemoveExpiredAsync"/> / <see cref="IRefreshTokenStore.RemoveExpiredAsync"/>).
/// Enabled with <see cref="PulseAuthOptions.EnableTokenCleanup"/>. Safe to run on several instances
/// at once: deletes are idempotent.
/// </summary>
public sealed class TokenCleanupService : BackgroundService
{
    private readonly IServiceScopeFactory          _scopeFactory;
    private readonly IOptions<PulseAuthOptions>    _options;
    private readonly ILogger<TokenCleanupService>? _logger;

    /// <summary>Initializes a new instance of the <see cref="TokenCleanupService"/> class.</summary>
    public TokenCleanupService(
        IServiceScopeFactory scopeFactory,
        IOptions<PulseAuthOptions> options,
        ILogger<TokenCleanupService>? logger = null)
    {
        _scopeFactory = scopeFactory;
        _options      = options;
        _logger       = logger;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var options = _options.Value;
        if (!options.EnableTokenCleanup)
            return;

        var interval = options.TokenCleanupInterval > TimeSpan.Zero
            ? options.TokenCleanupInterval
            : TimeSpan.FromHours(1);

        try
        {
            // Small random delay so several instances started together do not run in lockstep.
            await Task.Delay(TimeSpan.FromSeconds(Random.Shared.Next(5, 60)), stoppingToken);

            using var timer = new PeriodicTimer(interval);
            do
            {
                await RunOnceAsync(stoppingToken);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shutting down
        }
    }

    /// <summary>Runs one cleanup pass. Errors are logged, never thrown.</summary>
    public async Task RunOnceAsync(CancellationToken ct = default)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var codes  = scope.ServiceProvider.GetService<IAuthorizationCodeStore>();
            var tokens = scope.ServiceProvider.GetService<IRefreshTokenStore>();
            var refs   = scope.ServiceProvider.GetService<IReferenceTokenStore>();
            var revoked = scope.ServiceProvider.GetService<IRevokedTokenStore>();

            if (codes is not null)
                await codes.RemoveExpiredAsync(ct);
            if (tokens is not null)
                await tokens.RemoveExpiredAsync(ct);
            if (refs is not null)
                await refs.RemoveExpiredAsync(ct);
            if (revoked is not null)
                await revoked.RemoveExpiredAsync(ct);

            _logger?.LogDebug("PulseAuth token cleanup completed");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger?.LogError(ex, "PulseAuth token cleanup failed");
        }
    }
}
