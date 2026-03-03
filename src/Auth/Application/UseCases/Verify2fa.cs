using Auth.Domain;

namespace Auth.Application;

internal class Verify2fa
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ISecretProtector _protector;
    private readonly TwoFactorChallenge _twoFactorChallenge;

    public Verify2fa(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        ISecretProtector protector)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _protector = protector;
        _twoFactorChallenge = new(protector);
    }

    // 2. During login: verify TOTP using challenge token
    // After password verification, if user.TwoFactorEnabled => you should return a challenge token from login endpoint.
    // Here's the verify endpoint that consumes the challenge token and TOTP code, then signs in.
    public async Task<Result<Verify2faResult, Error>> Handle(string challengeToken, string code)
    {
        // Validate code
        if (string.IsNullOrWhiteSpace(code))
            return Result<Verify2faResult, Error>
              .Fail(new("NullOrEmptyCode", "Code cannot be null or empty"));

        // Validate challenge token
        var challengeResult = _twoFactorChallenge.Validate(challengeToken);
        if (!challengeResult.IsSuccess || challengeResult.Value == null)
            return Result<Verify2faResult, Error>
              .Fail(challengeResult.Error!);

        // Load user
        var user = await _userRepository.FindByIdAsync(challengeResult.Value.UserId);
        if (user is null)
            return Result<Verify2faResult, Error>
              .Fail(new("UserNotFound", "User not found"));

        // Verify TOTP code
        if (user.Is2faLocked())
            return Result<Verify2faResult, Error>
              .Fail(new("Locked", "Too many failed attempts"));

        bool ok;
        if (!user.TwoFactorEnabled || user.TwoFactorSecret == null)
        {
            ok = false;
        }
        else
        {
            var secret = _protector.Unprotect(user.TwoFactorSecret);
            ok = user.VerifyTotpAsync(secret, code);
        }

        if (!ok)
        {
            user.Register2faFailure();
            await _unitOfWork.SaveChangesAsync();
            return Result<Verify2faResult, Error>
              .Fail(new("InvalidTwoFactorCode", "Invalid 2FA code"));
        }

        user.Reset2faFailures();
        await _unitOfWork.SaveChangesAsync();

        // Build final result
        return Result<Verify2faResult, Error>
          .Success(new Verify2faResult
          (
              user.Id,
              user.Username,
              user.Email
          ));
    }
}
