using System.Security.Cryptography;
using OtpNet;

public class Setup2fa
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ISecretProtector _protector;
    private const int _secretSizeBytes = 20;    // 160-bit secret (recommended for TOTP)

    public Setup2fa(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        ISecretProtector protector)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _protector = protector;
    }

    // 1. Define result value
    public record class Value(
        string QrCodeDataUrl
    );

    // 2. Generate a secret + provisioning QR (user must be authenticated)
    public async Task<Result<Value, Error>> Handle(String issuer, Guid userId)
    {
        if (string.IsNullOrWhiteSpace(issuer))
            return Result<Value, Error>
              .Fail(new("NullOrEmptyIssuer", "Issuer cannot be null or empty"));

        if (userId == Guid.Empty)
            return Result<Value, Error>
              .Fail(new("EmptyUserId", "User Id cannot be empty"));

        var user = await _userRepository.FindByIdAsync(userId);
        if (user is null)
            return Result<Value, Error>
              .Fail(new("UserNotFound", "User not found"));

        // Generate secret and store temporarily in PendingTwoFactorSecret
        var secret = GenerateSecret();
        var qrDataUrl = user.BeginTwoFactorEnrollmentAsync(issuer, _protector.Protect(secret));

        await _unitOfWork.SaveChangesAsync();

        return Result<Value, Error>
          .Success(new Value(
              $"data:image/png;base64,{qrDataUrl}"
          ));
    }

    // Generate a new base32 secret for 2FA (not yet enabled for user)
    private string GenerateSecret()
    {
        var secretBytes = RandomNumberGenerator.GetBytes(_secretSizeBytes);
        return Base32Encoding.ToString(secretBytes);
    }
}
