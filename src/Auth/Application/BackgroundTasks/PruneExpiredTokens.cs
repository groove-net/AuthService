using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

public class PruneExpiredTokens : BackgroundService
{
    private readonly IUserRepository _userRepository;
    private readonly ILogger<PruneExpiredTokens> _logger;

    public PruneExpiredTokens(IUserRepository userRepository, ILogger<PruneExpiredTokens> logger)
    {
        _userRepository = userRepository;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Run forever until shutdown
        while (!stoppingToken.IsCancellationRequested)
        {
            // Prune expired tokens periodically
            await _userRepository.PruneExpiredPasswordResetTokens();
            // Run every hour
            await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
        }
    }
}
