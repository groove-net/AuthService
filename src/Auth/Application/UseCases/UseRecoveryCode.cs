using Microsoft.Extensions.Logging;
using Auth.Domain;

namespace Auth.Application;

// 1. Define result value
public record class UseRecoveryCodeResult
(
    Guid id,
    string username,
    string email
);

internal class UseRecoveryCode
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<Confirm2fa> _logger;
    private readonly ITwoFactorChallenge _twoFactorChallenge;

    public UseRecoveryCode(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        ILogger<Confirm2fa> logger,
        ITwoFactorChallenge twoFactorChallenege)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _logger = logger;
        _twoFactorChallenge = twoFactorChallenege;
    }

    // 2. Recovery code usage (during login 2FA phase)
    public async Task<Result<UseRecoveryCodeResult, Error>> Handle(string challengeToken, string recoveryCode)
    {
        // Validate recovery code
        if (string.IsNullOrWhiteSpace(recoveryCode))
            return Result<UseRecoveryCodeResult, Error>
              .Fail(new("NullOrEmptyRecoveryCode", "Recovery code cannot be null or empty"));

        // Validate challenge token
        var challengeResult = _twoFactorChallenge.Validate(challengeToken);
        if (!challengeResult.IsSuccess || challengeResult.Value == null)
            return Result<UseRecoveryCodeResult, Error>
              .Fail(challengeResult.Error!);

        // Load user
        var user = await _userRepository.FindByIdAsync(challengeResult.Value.UserId);
        if (user is null)
            return Result<UseRecoveryCodeResult, Error>
              .Fail(new("UserNotFound", "User not found"));

        // Consume recovery code
        if (user.Is2faLocked())
            return Result<UseRecoveryCodeResult, Error>
              .Fail(new("Locked", "Too many failed attempts"));

        var ok = user.ConsumeRecoveryCodeAsync(recoveryCode);

        if (!ok)
        {
            user.Register2faFailure();
            await _unitOfWork.SaveChangesAsync();
            //  Audit log here for account recovery investigations and abuse detection
            _logger.LogWarning("2FA recovery failure user={User} count={Count}", user.Username, user.TwoFactorFailureCount);
            return Result<UseRecoveryCodeResult, Error>
              .Fail(new("InvalidRecoveryCode", "Invalid recovery code"));
        }

        user.Reset2faFailures();
        await _unitOfWork.SaveChangesAsync();

        //  Audit log here for account recovery investigations and abuse detection
        _logger.LogInformation("2FA recovery code used by user={User}", user.Username); // also consider logging user metadata: { ip, userAgent })

        // Build final result
        return Result<UseRecoveryCodeResult, Error>
          .Success(new UseRecoveryCodeResult
          (
              user.Id,
              user.Username,
              user.Email
          ));
    }
}
