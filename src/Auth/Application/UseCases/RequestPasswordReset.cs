using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Auth.Domain;

namespace Auth.Application;

// 1. Define Response
public record RequestPasswordResetResult();

internal class RequestPasswordReset
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IEmailSender _emailSender;
    private readonly ILogger<RequestPasswordReset> _logger;

    public RequestPasswordReset(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IEmailSender emailSender,
        ILogger<RequestPasswordReset> logger)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _emailSender = emailSender;
        _logger = logger;
    }

    // 2. Handle method
    // Create a token and persist its hash
    public async Task<Result<RequestPasswordResetResult, Error>> Handle(string email)
    {
        // Validation
        var validation = new EmailValidator().Validate(email);
        if (!validation.IsValid)
            return Result<RequestPasswordResetResult, Error>
              .Fail(new Error("InvalidEmail", validation.Errors.First().ErrorMessage));

        // Get user
        var user = await _userRepository.FindByEmailAsync(email);
        if (user is null)
            return Result<RequestPasswordResetResult, Error>.Fail(new("UserNotFound", "A user with the provided email address could not be found"));

        //  audit log here for account recovery investigations and abuse detection
        _logger.LogTrace(message: $"Password reset request by {user.Username}"); // also consider logging metadata: { ip, userAgent })

        var tokensCreatedWithinLast5Minutes = await _userRepository.PasswordResetTokenCountWithinLastXMinutes(user.Id, 5);

        if (tokensCreatedWithinLast5Minutes >= 3)
            return Result<RequestPasswordResetResult, Error>.Fail(new("TooManyRequests", "Too many password reset requests. Please wait before trying again."));

        string tokenString;
        byte[] tokenBytes;
        byte[] tokenHash;
        try
        {
            (tokenString, tokenBytes) = CreateRandomToken();
            tokenHash = Sha256(tokenBytes);
        }
        catch
        {
            throw new Exception("Failed to create password reset token");
        }

        var pr = new PasswordResetToken(tokenHash);

        user.GrantPasswordResetToken(pr);
        user.AddDomainEvent(new PasswordResetTokenGrantedDomainEvent(user.Email, Uri.EscapeDataString(tokenString)));
        await _unitOfWork.SaveEntitiesAsync();

        return Result<RequestPasswordResetResult, Error>.Success(new RequestPasswordResetResult());
    }

    // Create URL-safe token string and return raw bytes too
    public static (string tokenString, byte[] tokenBytes) CreateRandomToken(int size = 32)
    {
        var bytes = RandomNumberGenerator.GetBytes(size);
        var token = Base64UrlEncode(bytes);
        return (token, bytes);
    }

    public static byte[] Sha256(byte[] data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        var base64 = Convert.ToBase64String(bytes);

        // Convert to Base64URL
        return base64
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
    }
}
