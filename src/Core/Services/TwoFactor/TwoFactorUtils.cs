using Core.Data;
using Core.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using OtpNet;
using QRCoder;

namespace Core.Services.TwoFactor;

public class TwoFactorUtils
{
  private const int TotpStepSeconds = 30;    // Each TOTP code is valid for 30 seconds
  private const int TotpDigits = 6;          // Standard 6-digit code
  private const int SecretSizeBytes = 20;    // 160-bit secret (recommended for TOTP)

  private readonly AppDbContext _db;
  private readonly ISecretProtector _protector;  // Handles encrypting/decrypting secrets

  public TwoFactorUtils(AppDbContext db, ISecretProtector protector)
  {
    _db = db;
    _protector = protector;
  }

  // Generate a new base32 secret for 2FA (not yet enabled for user)
  private string GenerateSecret()
  {
    var secretBytes = RandomNumberGenerator.GetBytes(SecretSizeBytes);
    return Base32Encoding.ToString(secretBytes);
  }

  // Build provisioning URI for authenticator apps (otpauth://)
  public string GetProvisioningUri(string base32Secret, string accountName, string issuer)
  {
    if (string.IsNullOrWhiteSpace(base32Secret))
      throw new ArgumentException("Secret is required", nameof(base32Secret));
    if (string.IsNullOrWhiteSpace(accountName))
      throw new ArgumentException("Account name is required", nameof(accountName));
    if (string.IsNullOrWhiteSpace(issuer))
      throw new ArgumentException("Issuer is required", nameof(issuer));

    var label = Uri.EscapeDataString($"{issuer}:{accountName}");
    var query =
        $"secret={Uri.EscapeDataString(base32Secret)}" +
        $"&issuer={Uri.EscapeDataString(issuer)}" +
        $"&algorithm=SHA1" +
        $"&digits={TotpDigits}" +
        $"&period={TotpStepSeconds}";

    return $"otpauth://totp/{label}?{query}";
  }

  // Generate a PNG QR code (returns byte array) for use in authenticator apps
  public byte[] GenerateQrCodePng(string provisioningUri, int pixelsPerModule = 20)
  {
    using var generator = new QRCodeGenerator();
    using var data = generator.CreateQrCode(provisioningUri, QRCodeGenerator.ECCLevel.Q);
    using var png = new PngByteQRCode(data);
    return png.GetGraphic(pixelsPerModule);
  }

  // Verify a TOTP code for a user, with optional allowed clock skew
  public async Task<bool> VerifyTotpAsync(
      User user,
      string code,
      int allowedDriftSteps = 1)
  {
    if (!user.TwoFactorEnabled || user.TwoFactorSecret == null)
      return false;

    code = code.Trim();
    if (code.Length != TotpDigits || !code.All(char.IsDigit))
      return false;

    var secret = _protector.Unprotect(user.TwoFactorSecret);
    var secretBytes = Base32Encoding.ToBytes(secret);

    var totp = new Totp(secretBytes, step: TotpStepSeconds, totpSize: TotpDigits);

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
    if (user.LastTotpStepUsed.HasValue && user.LastTotpStepUsed.Value >= matchedStep)
      return false;

    // Save last used TOTP step for replay protection
    user.LastTotpStepUsed = matchedStep;
    await _db.SaveChangesAsync();

    return true;
  }

  // Generate recovery codes, store hashed versions, return raw codes to user
  public async Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(User user, int count = 10)
  {
    var rawCodes = new List<string>(count);
    var hashes = new List<string>(count);

    for (int i = 0; i < count; i++)
    {
      var bytes = RandomNumberGenerator.GetBytes(10);
      var raw = NormalizeRecoveryCode(Base32Encoding.ToString(bytes)[..10]);

      rawCodes.Add(raw);
      hashes.Add(HashRecoveryCode(raw));
    }

    // Store hashes as JSON
    user.RecoveryCodesHashJson = JsonSerializer.Serialize(hashes);
    await _db.SaveChangesAsync();

    return rawCodes;
  }

  // Consume a recovery code: returns true if valid and removes it
  public async Task<bool> ConsumeRecoveryCodeAsync(User user, string rawCode)
  {
    if (string.IsNullOrWhiteSpace(user.RecoveryCodesHashJson))
      return false;

    var stored = JsonSerializer.Deserialize<List<string>>(user.RecoveryCodesHashJson) ?? new();

    var normalized = NormalizeRecoveryCode(rawCode);
    var hash = HashRecoveryCode(normalized);

    for (int i = 0; i < stored.Count; i++)
    {
      if (FixedTimeEqualsHex(stored[i], hash))
      {
        stored.RemoveAt(i);
        user.RecoveryCodesHashJson = JsonSerializer.Serialize(stored);
        await _db.SaveChangesAsync();
        return true;
      }
    }

    return false;
  }

  // Begin 2FA enrollment: store pending secret, but not yet enabled
  public async Task<string> BeginTwoFactorEnrollmentAsync(User user)
  {
    var secret = GenerateSecret();
    user.PendingTwoFactorSecret = _protector.Protect(secret);
    user.LastTotpStepUsed = null;
    await _db.SaveChangesAsync();
    return secret; // caller builds QR code from this
  }

  // Confirm 2FA enrollment: user provides first TOTP code to activate
  public async Task<bool> ConfirmTwoFactorEnrollmentAsync(User user, string code, int allowedDriftSteps = 1)
  {
    if (user.PendingTwoFactorSecret == null)
      return false;

    var secret = _protector.Unprotect(user.PendingTwoFactorSecret);
    var secretBytes = Base32Encoding.ToBytes(secret);

    var totp = new Totp(secretBytes, step: TotpStepSeconds, totpSize: TotpDigits);

    if (!totp.VerifyTotp(code, out long matchedStep, new VerificationWindow(previous: allowedDriftSteps, future: allowedDriftSteps)))
      return false;

    // Enable 2FA
    user.TwoFactorSecret = user.PendingTwoFactorSecret;
    user.PendingTwoFactorSecret = null;
    user.TwoFactorEnabled = true;
    user.LastTotpStepUsed = matchedStep;

    await _db.SaveChangesAsync();
    return true;
  }

  // Disable 2FA completely
  public async Task DisableTwoFactorAsync(User user)
  {
    user.TwoFactorEnabled = false;
    user.TwoFactorSecret = null;
    user.LastTotpStepUsed = null;
    user.RecoveryCodesHashJson = null;
    await _db.SaveChangesAsync();
  }

  /* =========================
     Helpers
     ========================= */

  // Normalize recovery codes (remove hyphens, uppercase)
  private static string NormalizeRecoveryCode(string code)
      => code.Replace("-", "").Trim().ToUpperInvariant();

  // SHA256 hash of a recovery code
  private static string HashRecoveryCode(string raw)
  {
    var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
    return Convert.ToHexString(bytes);
  }

  // Constant-time comparison to prevent timing attacks
  private static bool FixedTimeEqualsHex(string hexA, string hexB)
  {
    var a = Convert.FromHexString(hexA);
    var b = Convert.FromHexString(hexB);
    return CryptographicOperations.FixedTimeEquals(a, b);
  }
}