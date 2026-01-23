using Microsoft.Extensions.Logging;

public class Confirm2fa
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<Confirm2fa> _logger;
    private readonly ISecretProtector _protector;

    public Confirm2fa(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        ILogger<Confirm2fa> logger,
        ISecretProtector protector)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _logger = logger;
        _protector = protector;
    }

    // 1. Define result value
    public record class Value(IReadOnlyList<string> RecoveryCodes);

    // 2) Confirm the TOTP code to enable 2FA (user must be authenticated)
    public async Task<Result<Value, Error>> Handle(Guid userId, string code)
    {
        if (userId == Guid.Empty)
            return Result<Value, Error>
              .Fail(new("EmptyUserId", "User Id cannot be empty"));

        if (string.IsNullOrWhiteSpace(code))
            return Result<Value, Error>
              .Fail(new("NullOrEmptyCode", "Code cannot be null or empty"));

        var user = await _userRepository.FindByIdAsync(userId);
        if (user is null)
            return Result<Value, Error>
              .Fail(new("UserNotFound", "User not found"));

        // 2FA already enabled
        if (user.TwoFactorEnabled)
            return Result<Value, Error>
                .Fail(new("TwoFactorAlreadyEnabled", "2FA already enabled"));

        // Must have begun enrollment first
        if (user.PendingTwoFactorSecret == null)
            return Result<Value, Error>
                .Fail(new("TwoFactorNotInitialized", "2FA setup not initialized"));

        // Confirm enrollment (verifies TOTP + enables 2FA)
        var secret = _protector.Unprotect(user.PendingTwoFactorSecret);
        var confirmed = user.ConfirmTwoFactorEnrollmentAsync(secret, code);

        if (!confirmed)
            return Result<Value, Error>
                .Fail(new("InvalidCode", "Invalid code"));

        // Generate recovery codes AFTER successful confirmation
        var recoveryCodes = user.GenerateRecoveryCodesAsync(count: 10);

        await _unitOfWork.SaveChangesAsync();

        //  audit log here for account recovery investigations and abuse detection
        _logger.LogInformation("2FA enabled by user={User}", user.Username); // also consider logging user metadata: { ip, userAgent })

        return Result<Value, Error>
          .Success(new Value
          (
              recoveryCodes
          ));
    }
}
