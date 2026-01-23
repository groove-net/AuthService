using Microsoft.Extensions.Logging;

public class Disable2fa
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<Confirm2fa> _logger;

    public Disable2fa(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        ILogger<Confirm2fa> logger)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _logger = logger;
    }

    // 1. Define result value
    public record class Value();

    // 2. Disable2fa
    public async Task<Result<Value, Error>> Handle(Guid userId)
    {
        if (userId == Guid.Empty)
            return Result<Value, Error>
              .Fail(new("EmptyUserId", "User Id cannot be empty"));

        var user = await _userRepository.FindByIdAsync(userId);
        if (user is null)
            return Result<Value, Error>
              .Fail(new("UserNotFound", "User not found"));

        // Disable and wipe all 2FA state
        user.DisableTwoFactorAsync();

        await _unitOfWork.SaveChangesAsync();

        //  audit log here for account recovery investigations and abuse detection
        _logger.LogInformation("2FA disabled by user={User}", user.Username); // also consider logging user metadata: { ip, userAgent })

        return Result<Value, Error>.Success(new Value());
    }
}



