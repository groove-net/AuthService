using Auth.Domain;

namespace Auth.Application;

// 1. Define Response
public record ConfirmEmailResult();

internal class ConfirmEmail
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IConfirmationTokenGenerator _confirmationTokenGenerator;

    public ConfirmEmail(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IConfirmationTokenGenerator confirmationTokenGenerator)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _confirmationTokenGenerator = confirmationTokenGenerator;
    }

    // 2. Handle method
    public async Task<Result<ConfirmEmailResult, Error>> Handle(String token)
    {
        var payload = _confirmationTokenGenerator.ValidateConfirmationToken(token);

        if (payload == null)
            return Result<ConfirmEmailResult, Error>
              .Fail(new("InvalidToken", "Invalid token"));

        var user = await _userRepository.FindByIdAsync(payload.UserId);
        if (user is null)
            return Result<ConfirmEmailResult, Error>
              .Fail(new("UserNotFound", "User not found"));

        if (user.EmailConfirmed)
            return Result<ConfirmEmailResult, Error>
              .Fail(new("EmailAlreadyConfirmed", "Email already confirmed"));

        if (!string.Equals(user.Email, payload.UserEmail, StringComparison.OrdinalIgnoreCase))
            return Result<ConfirmEmailResult, Error>
              .Fail(new Error("StaleToken", "This confirmation link is no longer valid because the email address has changed."));

        user.ConfirmEmail();
        await _unitOfWork.SaveChangesAsync();

        return Result<ConfirmEmailResult, Error>.Success(new ConfirmEmailResult());
    }
}
