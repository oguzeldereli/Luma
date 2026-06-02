using Luma.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Luma.Infrastructure.Hosting
{
    /// <summary>
    /// Periodically removes expired authorization states and authorization codes from the database.
    /// Runs on every instance; the deletes are idempotent and safe to run concurrently.
    /// </summary>
    public class ExpiredGrantCleanupService : BackgroundService
    {
        private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

        private readonly IServiceScopeFactory _scopeFactory;
        private readonly ILogger<ExpiredGrantCleanupService> _logger;

        public ExpiredGrantCleanupService(
            IServiceScopeFactory scopeFactory,
            ILogger<ExpiredGrantCleanupService> logger)
        {
            _scopeFactory = scopeFactory;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    using var scope = _scopeFactory.CreateScope();
                    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                    var nowUtc = DateTime.UtcNow;

                    await context.AuthorizationCodeStates
                        .Where(s => s.ExpiresAtUtc <= nowUtc)
                        .ExecuteDeleteAsync(stoppingToken);

                    await context.AuthorizationCodes
                        .Where(c => c.Used || c.ExpiresAt <= nowUtc)
                        .ExecuteDeleteAsync(stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Expired grant cleanup failed.");
                }

                try
                {
                    await Task.Delay(Interval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }
}
