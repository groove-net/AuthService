using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

public class SendEmailConfirmation
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IEmailSender _emailSender;
    private readonly IDataProtector _protector;

    public SendEmailConfirmation(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IEmailSender emailSender,
        IDataProtector protector)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _emailSender = emailSender;
        _protector = protector;
    }

    // 2. Define Response
    public record Value();

    // 3. Handle method
    public async Task<Result<Value, Error>> Handle(Guid userId)
    {
        var user = await _userRepository.FindByIdAsync(userId);
        if (user is null)
            return Result<Value, Error>.Fail(new("UserNotFound", "User not found"));

        if (user.EmailConfirmed)
            return Result<Value, Error>.Fail(new("EmailAlreadyConfirmed", "Email already confirmed"));

        string token = GenerateEmailConfirmationToken(user.Id, user.Email);

        string confirmUrl = $"https://yourapp.com/auth/confirm-email?token={token}";

        Console.WriteLine("EMAIL CONFIRM LINK:");
        Console.WriteLine(confirmUrl);
        await _emailSender.SendEmailAsync(
            user.Email,
            "Welcome!",
            $"Thanks for registering! Here is your EMAIL CONFIRM LINK: {confirmUrl}");

        return Result<Value, Error>.Success(new Value());
    }

    private class EmailTokenPayload
    {
        public Guid UserId { get; set; }
        public String UserEmail { get; set; } = default!;
        public DateTime ExpiresAt { get; set; }
    }
    private string GenerateEmailConfirmationToken(Guid userId, String userEmail)
    {
        var payload = new EmailTokenPayload
        {
            UserId = userId,
            UserEmail = userEmail,
            ExpiresAt = DateTime.UtcNow.AddHours(1)
        };

        string json = JsonSerializer.Serialize(payload);
        string protectedData = _protector.Protect(json);

        return Uri.EscapeDataString(protectedData);
    }

}
