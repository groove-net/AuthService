public class UserLogin
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly TwoFactorChallenge _twoFactorChallenge; // for short-lived 2FA challenge tokens

    public UserLogin(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        ISecretProtector protector)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _twoFactorChallenge = new(protector);
    }

    public record class Value(
        Guid UserId,
        string Username,
        bool RequiresTwoFactore,
        string? ChallengeToken
    );

    public async Task<Result<Value, Error>> Handle(String username, String password)
    {
        // Validation
        var validation = new UsernameValidator().Validate(username);
        if (!validation.IsValid)
            return Result<Value, Error>
              .Fail(new Error("InvalidUsername", validation.Errors.First().ErrorMessage));
        validation = new PasswordValidator().Validate(password);
        if (!validation.IsValid)
            return Result<Value, Error>
              .Fail(new Error("InvalidPassword", validation.Errors.First().ErrorMessage));

        var user = await _userRepository.FindByUsernameAsync(username);

        if (user is null)
            // WARNING: consider performing a "dummy" hash comparison.
            // This prevents attackers from using timing differences to see if a username exists in your database.
            return Result<Value, Error>
              .Fail(new("InvalidCredentials", "Invalid username or password"));

        // Check lockout
        var minutesLeft = user.LockoutMinutesLeft();
        if (minutesLeft > 0)
            return Result<Value, Error>
              .Fail(new Error("Lockout", $"Account locked. Try again in {minutesLeft} minutes."));

        // Verify password
        bool passwordVerified = user.VerifyPassword(password);
        await _unitOfWork.SaveChangesAsync();

        if (!passwordVerified)
            return Result<Value, Error>
              .Fail(new("InvalidCredentials", "Invalid username or password"));

        // Check if email confirmed
        if (!user.EmailConfirmed)
            return Result<Value, Error>
              .Fail(new("EmailNotConfirmed", "Email not confirmed"));

        // --- 2FA step ---
        if (user.TwoFactorEnabled)
        {
            var challengeToken = _twoFactorChallenge.Create(user.Id);
            return Result<Value, Error>
              .Success(new Value
              (
                  user.Id,
                  user.Username,
                  true,
                  challengeToken
              ));
        }

        // No 2FA → return full user Value
        return Result<Value, Error>
          .Success(new Value
          (
              user.Id,
              user.Username,
              false,
              null
          ));
    }
}
