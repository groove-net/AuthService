using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Core.Services.PasswordReset;

namespace Core.Services.TokenPrune;

public class TokenPruneBackgroundService : BackgroundService
{
  private readonly IServiceProvider _services;

  public TokenPruneBackgroundService(IServiceProvider services)
  {
    _services = services;
  }

  protected override async Task ExecuteAsync(CancellationToken stoppingToken)
  {
    // Run forever until shutdown
    while (!stoppingToken.IsCancellationRequested)
    {
      try
      {
        using var scope = _services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<PasswordResetService>();

        await service.PruneExpiredAsync();
      }
      catch (Exception ex)
      {
        // log
        Console.WriteLine("Pruning failed: " + ex);
      }

      // Run every hour
      await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
    }
  }
}