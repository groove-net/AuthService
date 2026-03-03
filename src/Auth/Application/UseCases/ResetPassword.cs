using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Auth.Domain;

namespace Auth.Application;

internal class ResetPassword
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IEmailSender _emailSender;
    private readonly ILogger<ResetPassword> _logger;

    public ResetPassword(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IEmailSender emailSender,
        ILogger<ResetPassword> logger)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _emailSender = emailSender;
        _logger = logger;
    }

    // 2. Handle method
    // Validate token: returns User if valid, and marks token as used
    public async Task<Result<EmptyResult, Error>> Handle(string tokenString, string newPassword)
    {
        // Validate
        var validation = new PasswordValidator().Validate(newPassword);
        if (!validation.IsValid)
            return Result<EmptyResult, Error>
              .Fail(new Error("InvalidPassword", validation.Errors.First().ErrorMessage));

        // Hash token string
        byte[] tokenHash;
        try
        {
            tokenHash = Sha256FromTokenString(tokenString);
        }
        catch
        {
            throw new Exception("Failed to hash password reset token");
        }

        // Get token and user
        var token = await _userRepository.GetPasswordResetTokenInfo(tokenHash);
        if (token is null || token.User is null || token.ExpiresAt < DateTime.UtcNow)
            return Result<EmptyResult, Error>.Fail(new("InvalidToken", "Invalid or expired token"));
        var user = token.User;

        // Mark used (single-use)
        user.InvalidatePasswordResetTokens();

        //  audit log here for account recovery investigations and abuse detection
        _logger.LogTrace(message: $"Password reset used by {user.Username}"); // also consider logging metadata: { ip, userAgent })

        // Change password
        user.ResetPassword(newPassword);

        // Saved changes to Db
        await _unitOfWork.SaveChangesAsync();

        return Result<EmptyResult, Error>.Success(new EmptyResult());
    }

    private static byte[] Sha256FromTokenString(string tokenString)
    {
        var bytes = Base64UrlDecode(tokenString);
        return Sha256(bytes);
    }

    private static byte[] Sha256(byte[] data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }

    private static byte[] Base64UrlDecode(string base64Url)
    {
        var padded = base64Url
            .Replace("-", "+")
            .Replace("_", "/");

        // Add missing padding
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }

        return Convert.FromBase64String(padded);
    }
}
