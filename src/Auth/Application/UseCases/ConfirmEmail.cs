using Microsoft.AspNetCore.DataProtection;
using System.Text.Json;

public class ConfirmEmail
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IDataProtector _protector;

    public ConfirmEmail(
          IUserRepository userRepository,
          IUnitOfWork unitOfWork,
          IDataProtector protector)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _protector = protector;
    }

    // 1. Define Response
    public record Value();

    // 2. Handle method
    public async Task<Result<Value, Error>> Handle(string token)
    {
        var payload = ValidateEmailConfirmationToken(token);

        if (payload == null)
            return Result<Value, Error>
              .Fail(new("InvalidToken", "Invalid token"));

        var user = await _userRepository.FindByIdAsync(payload.UserId);
        if (user is null)
            return Result<Value, Error>
              .Fail(new("UserNotFound", "User not found"));

        if (user.EmailConfirmed)
            return Result<Value, Error>
              .Fail(new("EmailAlreadyConfirmed", "Email already confirmed"));

        if (!string.Equals(user.Email, payload.UserEmail, StringComparison.OrdinalIgnoreCase))
            return Result<Value, Error>
              .Fail(new Error("StaleToken", "This confirmation link is no longer valid because the email address has changed."));

        user.ConfirmEmail();
        await _unitOfWork.SaveChangesAsync();

        return Result<Value, Error>.Success(new Value());
    }

    private class EmailTokenPayload
    {
        public Guid UserId { get; set; }
        public String UserEmail { get; set; } = default!;
        public DateTime ExpiresAt { get; set; }
    }
    private EmailTokenPayload? ValidateEmailConfirmationToken(string token)
    {
        try
        {
            string protectedData = Uri.UnescapeDataString(token);
            string json = _protector.Unprotect(protectedData);

            var payload = JsonSerializer.Deserialize<EmailTokenPayload>(json);

            if (payload == null || payload.ExpiresAt < DateTime.UtcNow)
                return null;

            return payload;
        }
        catch
        {
            return null;
        }
    }

}
