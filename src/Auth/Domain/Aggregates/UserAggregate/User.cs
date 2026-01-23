using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using OtpNet;
using QRCoder;

public class User : Entity, IAggregateRoot
{
    public String Username { get; private set; }
    public String Email { get; private set; }
    public Boolean EmailConfirmed { get; private set; }

    // Password hash
    public Byte[] PasswordHash { get; private set; }
    public Byte[] PasswordSalt { get; private set; }
    private const Int32 _passwordIterations = 150_000; // Choose an iteration count suitable for modern hardware
    private const Byte _saltSize = 16; // 128-bit
    private const Byte _keySize = 32;  // 256-bit

    // Lockout
    public Byte FailedLoginAttempts { get; private set; }
    public DateTime? LockoutEnd { get; private set; }
    private const Byte _maxFailedAttempts = 5;
    private static readonly TimeSpan _lockoutDuration = TimeSpan.FromMinutes(15);

    // SecurityStamp
    public Guid SecurityStamp { get; private set; }

    // 2FA
    public Boolean TwoFactorEnabled { get; private set; }
    public String? TwoFactorSecret { get; private set; } // Store secret as Base32 String (OtpNet uses Base32)
    public String? RecoveryCodesHashJson { get; private set; } // Store recovery codes hashed (comma-separated hex or another table). Example as JSON String:
    public String? PendingTwoFactorSecret { get; private set; }
    public Int64? LastTotpStepUsed { get; private set; }
    public Byte TwoFactorFailureCount { get; private set; }
    public DateTime? TwoFactorLockoutUntil { get; private set; }
    private const Byte _totpStepSeconds = 30;    // Each TOTP code is valid for 30 seconds
    private const Byte _totpDigits = 6;          // Standard 6-digit code


    // Timestamps
    public DateTime CreatedAt { get; private set; }
    public DateTime? UpdatedAt { get; private set; }

    // Relationships
    public ICollection<PasswordResetToken> PasswordResetTokens { get; }

    // Constructor
    private User() { } // EF Core uses this via reflection
    public User(String username, String email, String password)
    {
        Username = username;
        Email = email;
        (PasswordHash, PasswordSalt) = HashPassword(password);
        EmailConfirmed = false;
        SecurityStamp = Guid.NewGuid();
        TwoFactorEnabled = false;
        CreatedAt = DateTime.UtcNow;
        PasswordResetTokens = [];
    }

    public void ConfirmEmail() => EmailConfirmed = true;

    public Boolean VerifyPassword(String password)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            PasswordSalt,
            _passwordIterations,
            HashAlgorithmName.SHA256
        );

        byte[] computed = pbkdf2.GetBytes(PasswordHash.Length);

        Boolean validPassword = CryptographicOperations.FixedTimeEquals(computed, PasswordHash);

        if (!validPassword)
        {
            FailedLoginAttempts++;

            // Lock account if too many failures
            if (FailedLoginAttempts >= _maxFailedAttempts)
            {
                LockoutEnd = DateTime.UtcNow.Add(_lockoutDuration);
                FailedLoginAttempts = 0; // reset counter after locking
            }

            return false;
        }

        // Successful login → reset attempts
        FailedLoginAttempts = 0;
        LockoutEnd = null;

        return true;
    }

    public void ChangePassword(String newPassword)
    {
        (PasswordHash, PasswordSalt) = HashPassword(newPassword);
        UpdatedAt = DateTime.UtcNow;
        SecurityStamp = Guid.NewGuid();
    }

    public Int32 LockoutMinutesLeft()
    {
        if (LockoutEnd.HasValue && LockoutEnd > DateTime.UtcNow)
            return (Int32)(LockoutEnd.Value - DateTime.UtcNow).TotalMinutes;
        return 0;
    }

    public void GrantPasswordResetToken(PasswordResetToken prt)
      => PasswordResetTokens.Add(prt);

    public void InvalidatePasswordResetTokens()
    {
        foreach (var prt in PasswordResetTokens)
            prt.InvalidateToken();
    }

    /**
     * 2FA Business Logic
     */

    // Begin 2FA enrollment: store pending secret, but not yet enabled
    public String BeginTwoFactorEnrollmentAsync(String issuer, String secret)
    {
        PendingTwoFactorSecret = secret;
        LastTotpStepUsed = null;

        var accountName = $"{issuer}:{Email}";

        var uri = GetProvisioningUri(secret, accountName, issuer);
        var qrDataUrl = Convert.ToBase64String(GenerateQrCodePng(uri));

        return qrDataUrl;
    }

    // Verify a TOTP code for a user, with optional allowed clock skew
    public Boolean VerifyTotpAsync(
        String secret,
        String code,
        Byte allowedDriftSteps = 1)
    {

        code = code.Trim();
        if (code.Length != _totpDigits || !code.All(char.IsDigit))
            return false;

        var secretBytes = Base32Encoding.ToBytes(secret);

        var totp = new Totp(secretBytes, step: _totpStepSeconds, totpSize: _totpDigits);

        // Verify code with drift window (± allowedDriftSteps)
        if (!totp.VerifyTotp(code, out long matchedStep, new VerificationWindow(previous: allowedDriftSteps, future: allowedDriftSteps)))
            return false;

        // Replay protection: reject if this TOTP step was already used
        // ------------------------------
        // WARN: Potential race condition:
        // Two requests arriving at the same time with the same code could both pass
        // before LastTotpStepUsed is saved. Minimal risk in most apps because:
        // - TOTP codes are short-lived (30s)
        // - Replay likely only matters for immediate account actions (login, sensitive operation)
        // Full mitigation requires DB-level atomic update or concurrency token.
        // For example, you can add a [Timestamp] or a UInt32 Version property to the User entity to enable Optimistic Concurrency.
        // This would solve the race condition by throwing a DbUpdateConcurrencyException if two TOTP attempts happen simultaneously.
        if (LastTotpStepUsed.HasValue && LastTotpStepUsed.Value >= matchedStep)
            return false;

        // Save last used TOTP step for replay protection
        LastTotpStepUsed = matchedStep;

        return true;
    }

    // Confirm 2FA enrollment: user provides first TOTP code to activate
    public Boolean ConfirmTwoFactorEnrollmentAsync(String secret, String code, Byte allowedDriftSteps = 1)
    {
        if (PendingTwoFactorSecret == null)
            return false;

        var secretBytes = Base32Encoding.ToBytes(secret);

        var totp = new Totp(secretBytes, step: _totpStepSeconds, totpSize: _totpDigits);

        if (!totp.VerifyTotp(code, out long matchedStep, new VerificationWindow(previous: allowedDriftSteps, future: allowedDriftSteps)))
            return false;

        // Enable 2FA
        TwoFactorSecret = PendingTwoFactorSecret;
        PendingTwoFactorSecret = null;
        TwoFactorEnabled = true;
        LastTotpStepUsed = matchedStep;

        return true;
    }

    // Disable 2FA completely
    public void DisableTwoFactorAsync()
    {
        TwoFactorEnabled = false;
        TwoFactorSecret = null;
        LastTotpStepUsed = null;
        RecoveryCodesHashJson = null;
    }

    // Generate recovery codes, store hashed versions, return raw codes to user
    public IReadOnlyList<String> GenerateRecoveryCodesAsync(Byte count = 10)
    {
        var rawCodes = new List<String>(count);
        var hashes = new List<String>(count);

        for (Byte i = 0; i < count; i++)
        {
            var bytes = RandomNumberGenerator.GetBytes(10);
            var raw = NormalizeRecoveryCode(Base32Encoding.ToString(bytes)[..10]);

            rawCodes.Add(raw);
            hashes.Add(HashRecoveryCode(raw));
        }

        // Store hashes as JSON
        RecoveryCodesHashJson = JsonSerializer.Serialize(hashes);

        return rawCodes;
    }

    // Consume a recovery code: returns true if valid and removes it
    public Boolean ConsumeRecoveryCodeAsync(String rawCode)
    {
        if (String.IsNullOrWhiteSpace(RecoveryCodesHashJson))
            return false;

        var stored = JsonSerializer.Deserialize<List<String>>(RecoveryCodesHashJson) ?? new();

        var normalized = NormalizeRecoveryCode(rawCode);
        var hash = HashRecoveryCode(normalized);

        for (Byte i = 0; i < stored.Count; i++)
        {
            if (FixedTimeEqualsHex(stored[i], hash))
            {
                stored.RemoveAt(i);
                RecoveryCodesHashJson = JsonSerializer.Serialize(stored);
                return true;
            }
        }

        return false;
    }

    public Boolean Is2faLocked()
    {
        return TwoFactorLockoutUntil != null
            && TwoFactorLockoutUntil > DateTime.UtcNow;
    }

    public void Register2faFailure()
    {
        TwoFactorFailureCount++;

        if (TwoFactorFailureCount >= 5)
        {
            TwoFactorLockoutUntil = DateTime.UtcNow.AddMinutes(5);
            TwoFactorFailureCount = 0; // reset counter after lockout
        }
    }

    public void Reset2faFailures()
    {
        TwoFactorFailureCount = 0;
        TwoFactorLockoutUntil = null;
    }

    /* =========================
       Helpers
       ========================= */

    // Build provisioning URI for authenticator apps (otpauth://)
    private String GetProvisioningUri(String base32Secret, String accountName, String issuer)
    {
        if (String.IsNullOrWhiteSpace(base32Secret))
            throw new ArgumentException("Secret is required", nameof(base32Secret));
        if (String.IsNullOrWhiteSpace(accountName))
            throw new ArgumentException("Account name is required", nameof(accountName));
        if (String.IsNullOrWhiteSpace(issuer))
            throw new ArgumentException("Issuer is required", nameof(issuer));

        var label = Uri.EscapeDataString($"{issuer}:{accountName}");
        var query =
            $"secret={Uri.EscapeDataString(base32Secret)}" +
            $"&issuer={Uri.EscapeDataString(issuer)}" +
            $"&algorithm=SHA1" +
            $"&digits={_totpDigits}" +
            $"&period={_totpStepSeconds}";

        return $"otpauth://totp/{label}?{query}";
    }

    // Generate a PNG QR code (returns byte array) for use in authenticator apps
    private byte[] GenerateQrCodePng(String provisioningUri, Byte pixelsPerModule = 20)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(provisioningUri, QRCodeGenerator.ECCLevel.Q);
        using var png = new PngByteQRCode(data);
        return png.GetGraphic(pixelsPerModule);
    }

    // Normalize recovery codes (remove hyphens, uppercase)
    private static String NormalizeRecoveryCode(String code)
        => code.Replace("-", "").Trim().ToUpperInvariant();

    // SHA256 hash of a recovery code
    private static String HashRecoveryCode(String raw)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes);
    }

    // Constant-time comparison to prevent timing attacks
    private static Boolean FixedTimeEqualsHex(String hexA, String hexB)
    {
        var a = Convert.FromHexString(hexA);
        var b = Convert.FromHexString(hexB);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    private (byte[] hash, byte[] salt) HashPassword(String password)
    {
        // Create salt
        byte[] salt = RandomNumberGenerator.GetBytes(_saltSize);

        // Derive key
        using var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            salt,
            _passwordIterations,
            HashAlgorithmName.SHA256
        );

        byte[] hash = pbkdf2.GetBytes(_keySize);

        return (hash, salt);
    }

}
