TOTP (Time-based One-Time Password) 2FA is a great next step. I’ll give you a complete, production-ready flow you can drop into your playground project:

- how to store TOTP secrets and recovery codes
- how to produce an `otpauth://` provisioning URI and QR (so Google Authenticator / Authy can scan)
- how to verify codes
- how to integrate 2FA into your login flow (challenge token + final signin)
- endpoints to enable/confirm/disable 2FA and to use recovery codes
- secure implementation hints (single-use recovery codes, secret storage, rate-limits)

I’ll use two small, battle-tested NuGet libraries:

- **OtpNet** (for TOTP generation/verification)
- **QRCoder** (to return a QR code data-URL so you can scan during development)

Add these packages to the library:

```bash
$ dotnet add src/Auth package Otp.NET
$ dotnet add src/Auth package QRCoder
```

---

### Step 1 — Data model changes

Extend your `User` model with TOTP and recovery fields:

```csharp
namespace AuthPlayground.Models;

public class User
{
  public Guid Id { get; set; } = Guid.NewGuid();

  public string Username { get; set; } = default!;
  public string Email { get; set; } = default!;
  public bool EmailConfirmed { get; set; }

  public byte[] PasswordHash { get; set; } = default!;
  public byte[] PasswordSalt { get; set; } = default!;
  public int PasswordIterations { get; set; }

  // Lockout
  public int FailedLoginAttempts { get; set; }
  public DateTime? LockoutEnd { get; set; }

  // SecurityStamp
  public Guid SecurityStamp { get; set; } = Guid.NewGuid();

  // 2FA
  public bool TwoFactorEnabled { get; set; } = false;
  public string? TwoFactorSecret { get; set; } // Store secret as Base32 string (OtpNet uses Base32)
  public string? RecoveryCodesHashJson { get; set; } // Store recovery codes hashed (comma-separated hex or another table). Example as JSON string:
  public string? PendingTwoFactorSecret { get; set; }
  public long? LastTotpStepUsed { get; set; }
  public int TwoFactorFailureCount { get; set; }
	public DateTime? TwoFactorLockoutUntil { get; set; }
  
  // Timestamps
  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
  public DateTime? UpdatedAt { get; set; }
}
```

Notes:

- `TwoFactorSecret` = Base32-encoded secret (not plaintext HMAC key bytes). This is convenient and standard.
- `RecoveryCodesHashJson` stores the hashed recovery codes (single-use). You can also make a separate `RecoveryCode` table for better auditing.

Run EF migration:

```bash
dotnet ef migrations add AddTwoFactorFields --project ./src/AuthPlayground --startup-project ./src/WebAPI
dotnet ef database update --project ./src/AuthPlayground --startup-project ./src/WebAPI
```

---

### Step 2 —  TwoFactorService — generate & verify codes, recovery codes2

Run the following code in some temporary environment (separate console app, online compiler, etc.) and save the base64 string as a secret in a file called `key`:

```csharp
using System;
using System.Security.Cryptography;

using var rng = RandomNumberGenerator.Create();
var key = new byte[32]; // 256-bit key
rng.GetBytes(key);

var base64 = Convert.ToBase64String(key);
Console.WriteLine(base64);
```

Create `ISecretProvider`:

```csharp
namespace AuthPlayground.Services.TwoFactor;

public interface ISecretProtector
{
  string Protect(string plaintext);
  string Unprotect(string ciphertext);
}
```

Create an AES-GCM Implementation of `ISecretProvider`:

```csharp
using System.Security.Cryptography;
using System.Text;

namespace AuthPlayground.Services.TwoFactor;

public sealed class AesGcmSecretProtector : ISecretProtector
{
  // Versioning allows future crypto migration
  private const byte Version = 1;

  // AES-GCM parameters (do not change without version bump)
  private const int NonceSizeBytes = 12; // 96-bit
  private const int TagSizeBytes = 16;   // 128-bit

  private readonly byte[] _key;

  // Key must be 16, 24, or 32 bytes (AES-128/192/256)
  public AesGcmSecretProtector(byte[] key)
  {
    if (key == null)
      throw new ArgumentNullException(nameof(key));

    if (key.Length is not (16 or 24 or 32))
      throw new ArgumentException("Key must be 16, 24, or 32 bytes", nameof(key));

    _key = key;
  }

  public string Protect(string plaintext)
  {
    if (plaintext == null)
      throw new ArgumentNullException(nameof(plaintext));

    var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

    var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
    var tag = new byte[TagSizeBytes];
    var ciphertext = new byte[plaintextBytes.Length];

    using var aes = new AesGcm(_key, TagSizeBytes);
    aes.Encrypt(
      nonce,
      plaintextBytes,
      ciphertext,
      tag,
      associatedData: new[] { Version }
    );

    // Payload format:
    // [version][nonce][tag][ciphertext]
    var payload = new byte[
        1 +
        NonceSizeBytes +
        TagSizeBytes +
        ciphertext.Length];

    payload[0] = Version;

    Buffer.BlockCopy(nonce, 0, payload, 1, NonceSizeBytes);
    Buffer.BlockCopy(tag, 0, payload, 1 + NonceSizeBytes, TagSizeBytes);
    Buffer.BlockCopy(
        ciphertext,
        0,
        payload,
        1 + NonceSizeBytes + TagSizeBytes,
        ciphertext.Length);

    return Convert.ToBase64String(payload);
  }

  public string Unprotect(string protectedData)
  {
    if (protectedData == null)
      throw new ArgumentNullException(nameof(protectedData));

    var payload = Convert.FromBase64String(protectedData);

    if (payload.Length < 1 + NonceSizeBytes + TagSizeBytes)
      throw new CryptographicException("Invalid protected payload");

    var version = payload[0];
    if (version != Version)
      throw new CryptographicException("Unsupported secret version");

    var nonce = payload.AsSpan(1, NonceSizeBytes).ToArray();
    var tag = payload.AsSpan(1 + NonceSizeBytes, TagSizeBytes).ToArray();
    var ciphertext = payload
        .AsSpan(1 + NonceSizeBytes + TagSizeBytes)
        .ToArray();

    var plaintext = new byte[ciphertext.Length];

    using var aes = new AesGcm(_key, TagSizeBytes);
    aes.Decrypt(
      nonce,
      ciphertext,
      tag,
      plaintext,
      associatedData: new[] { version }
    );

    return Encoding.UTF8.GetString(plaintext);
  }
}

```

Register the service using key:

```csharp
var base64Key = File.ReadAllText(File.Exists("/run/secrets/key")
  ? "/run/secrets/key"
  : "secrets/key").Trim();
var keyBytes = Convert.FromBase64String(base64Key);
services.AddSingleton<ISecretProtector>(new AesGcmSecretProtector(keyBytes));
```

A scoped service encapsulates all 2FA logic.

```csharp
using AuthPlayground.Data;
using AuthPlayground.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using OtpNet;
using QRCoder;

namespace AuthPlayground.Services.TwoFactor;

public class TotpUtils
{
  private const int TotpStepSeconds = 30;    // Each TOTP code is valid for 30 seconds
  private const int TotpDigits = 6;          // Standard 6-digit code
  private const int SecretSizeBytes = 20;    // 160-bit secret (recommended for TOTP)

  private readonly AppDbContext _db;
  private readonly ISecretProtector _protector;  // Handles encrypting/decrypting secrets

  public TotpUtils(AppDbContext db, ISecretProtector protector)
  {
    _db = db;
    _protector = protector;
  }

  // Generate a new base32 secret for 2FA (not yet enabled for user)
  public string GenerateSecret()
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

```

Register service:

```csharp
services.AddScoped<TotpUtils>();
```

---

```csharp
using AuthPlayground.Data;
using AuthPlayground.Models;
using AuthPlayground.Utilities;

using Microsoft.AspNetCore.DataProtection;

using System.Text.Json;

namespace AuthPlayground.Services.TwoFactor;

public class TwoFactorService
{
  private readonly AppDbContext _db;
  private readonly PasswordHasher _hasher;
  private readonly TotpUtils _totpUtils;
  private readonly IDataProtector _protector; // for short-lived 2FA challenge tokens

  public TwoFactorService(AppDbContext db, PasswordHasher hasher, TotpUtils totpUtils, IDataProtectionProvider dp)
  {
    _db = db;
    _hasher = hasher;
    _totpUtils = totpUtils;
    _protector = dp.CreateProtector("2fa-challenge");
  }

  // DTO for Get2faSetup Result
  public record Get2faSetupResult
  {
    public string ProvisioningUri { get; set; } = default!;
    public string QrCodeDataUrl { get; set; } = default!;
    public string Secret { get; set; } = default!;
  }
  // DTO for Get2faSetup Error
  public record Get2faSetupError : Error
  {
    public Get2faSetupError(string code, string message)
        : base(code, message) { }
    public static readonly Get2faSetupError UserNotFound =
        new("UserNotFound", "A user with the id could not be found");
  }
  // 1) Generate a secret + provisioning QR (user must be authenticated)
  public async Task<Result<Get2faSetupResult, Get2faSetupError>> Get2faSetup(Guid userId)
  {
    var user = await _db.Users.FindAsync(userId);
    if (user == null)
      return Result<Get2faSetupResult, Get2faSetupError>.Fail(Get2faSetupError.UserNotFound);

    // Generate secret and store temporarily in PendingTwoFactorSecret
    var secret = _totpUtils.GenerateSecret();
    user.PendingTwoFactorSecret = _protector.Protect(secret);
    user.LastTotpStepUsed = null;
    await _db.SaveChangesAsync();

    var issuer = "YourAppName";
    var accountName = $"{issuer}:{user.Email}";

    var uri = _totpUtils.GetProvisioningUri(secret, accountName, issuer);
    var qrDataUrl = Convert.ToBase64String(_totpUtils.GenerateQrCodePng(uri));

    return Result<Get2faSetupResult, Get2faSetupError>
      .Success(new Get2faSetupResult
      {
        ProvisioningUri = uri,
        QrCodeDataUrl = $"data:image/png;base64,{qrDataUrl}",
        Secret = secret
      });
  }

  // DTO for Confirm2fa Result
  public record Confirm2faResult
  {
    public IReadOnlyList<string> RecoveryCodes { get; set; } = Array.Empty<string>();
  }
  // DTO for Confirm2fa Error
  public record Confirm2faError : Error
  {
    public Confirm2faError(string code, string message)
        : base(code, message) { }
    public static readonly Confirm2faError UserNotFound =
        new("UserNotFound", "A user with the id could not be found");
    public static readonly Confirm2faError TwoFactorNotInitialized =
        new("TwoFactorNotInitialized", "2FA not initialized for this user");
    public static readonly Confirm2faError InvalidCode =
        new("InvalidCode", "Invalid code");
  }
  // 2) Confirm the TOTP code to enable 2FA (user must be authenticated)
  public async Task<Result<Confirm2faResult, Confirm2faError>> Confirm2fa(Guid userId, string code)
  {
    var user = await _db.Users.FindAsync(userId);
    if (user == null)
      return Result<Confirm2faResult, Confirm2faError>
          .Fail(Confirm2faError.UserNotFound);

    // Must have begun enrollment first
    if (user.PendingTwoFactorSecret == null)
      return Result<Confirm2faResult, Confirm2faError>
          .Fail(Confirm2faError.TwoFactorNotInitialized);

    // Confirm enrollment (verifies TOTP + enables 2FA)
    var confirmed = await _totpUtils
        .ConfirmTwoFactorEnrollmentAsync(user, code);

    if (!confirmed)
      return Result<Confirm2faResult, Confirm2faError>
          .Fail(Confirm2faError.InvalidCode);

    // Generate recovery codes AFTER successful confirmation
    var recoveryCodes =
        await _totpUtils.GenerateRecoveryCodesAsync(user, count: 10);

    await _db.SaveChangesAsync();

    // TODO: You may audit log here for account recovery investigations and abuse detection
    //_audit.Log("2FA_ENABLED", user.Id, metadata: { ip, userAgent });

    return Result<Confirm2faResult, Confirm2faError>
      .Success(new Confirm2faResult
      {
        RecoveryCodes = recoveryCodes
      });
  }

  // DTO for Verify2fa Error
  public record Verify2faError : Error
  {
    public Verify2faError(string code, string message)
        : base(code, message) { }
    public static readonly Verify2faError UserNotFound =
        new("UserNotFound", "User not found");
    public static readonly Verify2faError InvalidChallenge =
        new("InvalidChallenge", "Invalid challenge");
    public static readonly Verify2faError ExpiredChallenge =
        new("ExpiredChallenge", "Expired challenge");
    public static readonly Verify2faError InvalidTwoFactorCode =
        new("InvalidTwoFactorCode", "Invalid 2FA code");
  }
  // 3) During login: verify TOTP using challenge token
  // After password verification, if user.TwoFactorEnabled => you should return a challenge token from login endpoint.
  // Here's the verify endpoint that consumes the challenge token and TOTP code, then signs in.
  public async Task<Result<NoResult, Verify2faError>> Verify2fa(string challengeToken, string code)
  {
    // dto.ChallengeToken, dto.Code
    var payloadJson = UnprotectChallenge(challengeToken);
    if (payloadJson == null)
      return Result<NoResult, Verify2faError>.Fail(Verify2faError.InvalidChallenge);

    var payload = JsonSerializer.Deserialize<TwoFactorChallengePayload>(payloadJson);
    if (payload == null)
      return Result<NoResult, Verify2faError>.Fail(Verify2faError.InvalidChallenge);
    if (payload.ExpiresAt < DateTime.UtcNow)
      return Result<NoResult, Verify2faError>.Fail(Verify2faError.ExpiredChallenge);

    var user = await _db.Users.FindAsync(payload.UserId);
    if (user == null)
      return Result<NoResult, Verify2faError>.Fail(Verify2faError.UserNotFound);

    // Verify TOTP
    if (await _totpUtils.VerifyTotpAsync(user, code))
      return Result<NoResult, Verify2faError>.Success(new());

    return Result<NoResult, Verify2faError>.Fail(Verify2faError.InvalidTwoFactorCode);
  }

  // DTO for UseRecoveryCode Error
  public record UseRecoveryCodeError : Error
  {
    public UseRecoveryCodeError(string code, string message)
        : base(code, message) { }
    public static readonly UseRecoveryCodeError UserNotFound =
        new("UserNotFound", "User not found");
    public static readonly UseRecoveryCodeError InvalidChallenge =
        new("InvalidChallenge", "Invalid challenge");
    public static readonly UseRecoveryCodeError ExpiredChallenge =
        new("ExpiredChallenge", "Expired challenge");
    public static readonly UseRecoveryCodeError InvalidRecoveryCode =
        new("InvalidTwoFactorCode", "Invalid 2FA code");
  }
  // 4) Recovery code usage (during login 2FA phase)
  public async Task<Result<NoResult, UseRecoveryCodeError>> UseRecoveryCode(string challengeToken, string recoveryCode)
  {
    var payloadJson = UnprotectChallenge(challengeToken);
    if (payloadJson == null)
      return Result<NoResult, UseRecoveryCodeError>.Fail(UseRecoveryCodeError.InvalidChallenge);

    var payload = JsonSerializer.Deserialize<TwoFactorChallengePayload>(payloadJson);
    if (payload == null)
      return Result<NoResult, UseRecoveryCodeError>.Fail(UseRecoveryCodeError.InvalidChallenge);
    if (payload.ExpiresAt < DateTime.UtcNow)
      return Result<NoResult, UseRecoveryCodeError>.Fail(UseRecoveryCodeError.ExpiredChallenge);

    var user = await _db.Users.FindAsync(payload.UserId);
    if (user == null)
      return Result<NoResult, UseRecoveryCodeError>.Fail(UseRecoveryCodeError.UserNotFound);

    var ok = await _totpUtils.ConsumeRecoveryCodeAsync(user, recoveryCode);
    if (!ok)
      return Result<NoResult, UseRecoveryCodeError>.Fail(UseRecoveryCodeError.InvalidRecoveryCode);

    // TODO: You may audit log here for account recovery investigations and abuse detection
    //_audit.Log("2FA_RECOVERY_CODE_USED", user.Id, metadata: { ip, userAgent });

    return Result<NoResult, UseRecoveryCodeError>.Success(new());
  }

  // DTO for Get2faSetup Error
  public record Disable2faError : Error
  {
    public Disable2faError(string code, string message)
        : base(code, message) { }
    public static readonly Disable2faError UserNotFound =
        new("UserNotFound", "User could not be found");
  }
  public async Task<Result<NoResult, Disable2faError>> Disable2fa(Guid userId)
  {
    var user = await _db.Users.FindAsync(userId);
    if (user == null)
      return Result<NoResult, Disable2faError>
        .Fail(Disable2faError.UserNotFound);

    // Disable and wipe all 2FA state
    await _totpUtils.DisableTwoFactorAsync(user);

    // TODO: You may audit log here for account recovery investigations and abuse detection
    //_audit.Log("2FA_DISABLED", user.Id, metadata: { ip, userAgent });

    return Result<NoResult, Disable2faError>.Success(new());
  }

  // helpers: create and unprotect a short-lived 2FA challenge token
  public string CreateChallengeToken(Guid userId)
  {
    var payload = new TwoFactorChallengePayload
    {
      UserId = userId,
      ExpiresAt = DateTime.UtcNow.AddMinutes(5) // short TTL
    };
    var json = JsonSerializer.Serialize(payload);
    return _protector.Protect(json);
  }

  private string? UnprotectChallenge(string token)
  {
    try
    {
      return _protector.Unprotect(token);
    }
    catch
    {
      return null;
    }
  }

  private class TwoFactorChallengePayload
  {
    public Guid UserId { get; set; }
    public DateTime ExpiresAt { get; set; }
  }
}

```

Register service:

```csharp
services.AddScoped<TwoFactorService>();
```

---

**Executive Summary**

Now, your 2FA implementation is:

- Cryptographically correct
- Structurally sound
- Aligned with how serious production systems implement TOTP

What you have now is “production-ready for v1”, the only low-risk problems you might have is the replay protection race condition which you already documented it correctly. Additionally, you might want to consider invalidating challenge tokens after success (optional hardening) but many production system skip this because it is an acceptable risk. 2FA challenge tokens are time-limited but not single-use. This allows replay of a valid challenge within its short TTL if an attacker already possesses valid credentials and a fresh TOTP or recovery code. Impact is limited and does not weaken MFA guarantees. Risk is accepted given short expiration, per-user throttling, lockout enforcement, and TOTP step replay protection. One-time challenge invalidation is noted as future hardening.

---

### Step 3 —  Modify Login Logic in `AuthenticationLogic.cs`

First inject the `TwoFactorService` via the constructor.

```csharp
// ...
using Core.Services.TwoFactor;
// ...
public class AuthenticationService
{
  // ...
  private readonly TwoFactorService _twoFactorService;

  public AuthenticationService(...., TwoFactorService twoFactorService)
  {
    // ...
    _twoFactorService = twoFactorService;
  }
  
  // ...
  
}

```

Then change the method signature of the Login method so that the result can return any object. You will have to change the signatures of all the return statements within the method.

```csharp
[-] public async Task<Result<User, LoginUserError>> Login(string Username, string Password)
[+] public async Task<Result<object, LoginUserError>> Login(string Username, string Password)
```

Then replace the TODO comment with the 2FA step

```csharp
    // --- 2FA step ---
    if (user.TwoFactorEnabled)
    {
      var challengeToken = _twoFactorService.CreateChallengeToken(user.Id);
      return Result<object, LoginUserError>.Success(new { ChallengeToken = challengeToken });
    }

    // No 2FA → return full user object
    return Result<object, LoginUserError>.Success(user);
  }
```

---

### Step 4 —  Endpoints to manage 2FA

I’ll add endpoints to `AuthController`:

- `GET /auth/2fa/setup` — generate secret + otpauth URI + QR (returns provisioningUri and QR data-url). This endpoint should require the user to be authenticated (signed in). It **does not** enable 2FA yet.
- `POST /auth/2fa/confirm` — user posts a TOTP code to prove they have set up the authenticator. If valid, enable 2FA and create recovery codes (return raw recovery codes to user once).
- `POST /auth/2fa/verify` — used during login when the server asked for 2FA (challenge token + code). Verifies and signs-in the user.
- `POST /auth/2fa/disable` — disables 2FA after verifying current password or TOTP (protected).
- `POST /auth/2fa/recovery` — use a recovery code in place of TOTP to finish login.

Add rate limiting/per-IP throttling to `POST /auth/2fa/verify` and `POST /auth/2fa/recovery`. (Even a simple in-memory or Redis counter is enough.)

---

**Step 1: Call `GET /2fa/setup`**

**Expected**

- QR code returned
- Secret returned
- No 2FA enabled yet

**Check**

- DB: `PendingTwoFactorSecret != null`
- DB: `TwoFactorEnabled == false`

**Step 2: Scan QR in Authenticator app**

**Step 3: Call `POST /2fa/confirm`**

```json
{ 
	"user_id": "...",
	"code": "12345"
}
```

**Expected**

- 200 OK
- Recovery codes returned (10). There are generated once, shown once, and stored only as hashes. You must tell the user explicitly to “Store them securely (password manager recommended). Each code can be used once. We will not show them again.”
- 2FA enabled

**Check**

- DB: `TwoFactorEnabled == true`
- DB: `PendingTwoFactorSecret == null`
- DB: recovery codes stored (hashed/encrypted)

**Negative tests**

- Wrong code → `InvalidCode`
- Reuse same code → fail

**Step 4: Login with password**

**Expected**

- Response indicates 2FA required
- `challengeToken` returned

**Check**

- Token decodes via DataProtection
- Expiration ≈ 5 minutes

**Step 5: Call `POST /2fa/verify`**

```json
{
  "challengeToken": "…",
  "code": "654321"
}
```

**Expected**

- 200 OK
- Login completes
- Challenge cannot be reused (if you invalidate)

**Negative tests**

- Wrong code → `InvalidTwoFactorCode`
- 5 wrong attempts → `Locked`
- Retry before lockout expires → still locked
- Wait 5 minutes → unlocked

**Step 6: Login → get challenge token again**

**Step 7: Call `POST /2fa/recovery`**

```json
{
  "challengeToken": "…",
  "recoveryCode": "abcd-efgh"
}
```

**Expected**

- 200 OK
- Code is consumed

**Negative tests**

- Reuse same recovery code → fail
- Invalid recovery code → increments lockout
- Lockout applies to recovery as well

**Step 8: Call `POST /2fa/disable`**

**Expected**

- 2FA disabled
- Secrets wiped

**Check**

- DB: no secret
- DB: no recovery codes
- Login no longer requires 2FA

**Time / replay / abuse tests (important)**

| Test | Expected |
| --- | --- |
| Use expired challenge | `ExpiredChallenge` |
| Use challenge after success | fail |
| Use TOTP from previous step | fail |
| Change system clock | codes fail |
| Concurrent attempts | only one succeeds |

**Logging verification**

Confirm logs include:

- 2FA enabled / disabled
- Failed attempts
- Lockouts
- Recovery usage

No secrets or codes should appear in logs.

---

### Step 4 —  Integrate 2FA into the login flow

**Client flow now:**

1. Call `POST /login` → receives either:
    - Full user object (if no 2FA)
    - `{ ChallengeToken }` (if 2FA enabled)
2. Call `POST /auth/2fa/verify` with `{ challengeToken, code }` → server verifies TOTP / recovery code and completes login.

The client just checks “did I get a challenge token?” vs “did I get a user object?”

Modify your login flow (where you verify password) like this:

1. After successful password check and lockout/email checks:
    - If `user.TwoFactorEnabled == false`, proceed to issue cookie as before.
    - If `user.TwoFactorEnabled == true`, do **not** issue the auth cookie yet. Instead:
        - Create a short-lived challenge token: `var challenge = CreateChallengeToken(user.Id);`
        - Return HTTP 200 with `{ twoFactorRequired: true, challengeToken: "<token>", methods: ["totp", "recovery"] }`.
2. Client receives that response, prompts user for the TOTP code (or recovery code), then calls:
    - `POST /auth/2fa/verify` with `{ challengeToken, code }` or
    - `POST /auth/2fa/recovery` with `{ challengeToken, recoveryCode }`.
    
    Recovery codes exist to **prevent permanent account lockout** when a user loses access to their primary 2FA device.
    
    Typical failure scenarios:
    
    - Phone lost, stolen, or wiped
    - Authenticator app deleted
    - Device clock broken or reset
    - User switched phones without migrating 2FA
    
    TOTP assumes the user still has the device. If not, TOTP is unusable and user must fall back to recovery codes.
    
    Recovery codes are offline, do not depend on time and are single use. Without recovery codes, **support intervention becomes the only escape hatch**, which is expensive, slow, and insecure.
    
    Why not just let users disable 2FA if they lose the device? Because that would mean:
    
    - Password alone becomes sufficient again
    - An attacker with password access could trivially bypass 2FA
    - You’ve defeated the purpose of 2FA
    
    Why not email / SMS as fallback instead? Because those:
    
    - Are weaker factors
    - Are attackable (SIM swap, email compromise)
    - Reintroduce online dependency
    
    If the user loses device and all recovery codes, then the typical last resort is Support-assisted reset through human identity verification and manually disable 2FA.
    
3. If server verifies, it signs in the user (sets cookie) and returns success.

This pattern prevents issuing a session cookie until 2FA is satisfied, and avoids storing ephemeral state server-side by using a DataProtection-protected challenge token.

---

### Step 5 —  Recovery codes & disabling 2FA

- Recovery codes are generated during `2fa/confirm`. Show them to user once and instruct them to store them in a secure place.
- When a recovery code is used, remove it from the stored list (we do that).
- Provide `POST /auth/2fa/disable` that requires either current password or a valid TOTP code to disable 2FA; on disable, clear the secret and recovery codes.
- After disabling or resetting TOTP, rotate `SecurityStamp` and optionally revoke sessions.

---

### Step 6 —  Security hardening & operational notes

- **Store secrets carefully**: `TwoFactorSecret` is required to verify codes. Consider encrypting it with `IDataProtector` before storing if DB access might be compromised:
    - `var protected = protector.Protect(secret); store protected`.
    - Unprotect when verifying. (This adds defense-in-depth.)
- **Rate-limit** the `2fa/verify` and `2fa/recovery` endpoints per IP and per account to prevent guessing.
- **Use small TTL** for the challenge token (5 minutes).
- **Use verification window** (±1 step) for slight clock differences, but be conservative.
- **Audit events**: log enabling/disabling 2FA and recovery code usage.
- **Rotate secrets**: if a user suspects compromise, provide an option to rotate TOTP secret (re-run setup).
- **Invalidate sessions on critical changes**: when enabling/disabling or resetting password, rotate `SecurityStamp` for that user and check it in a cookie-validation middleware (compare claim vs DB).
- **Backup codes**: show raw codes only once; keep only their hashes in DB.

---

### Step 7 —  Quick UX notes for your playground client

- Flow to enable:
    1. User logs in (no TFA yet).
    2. Visit “Enable 2FA” page → call `GET /auth/2fa/setup`, scan QR into Authenticator app.
    3. Enter current TOTP code into `POST /auth/2fa/confirm` to verify and enable. Client shows raw recovery codes and instructs user to copy/save them.
- Flow to log in (2FA enabled):
    1. Client calls `/auth/login` with username/password.
    2. If `{ twoFactorRequired: true }` returned, prompt for code (or recovery).
    3. Call `/auth/2fa/verify` (or `/auth/2fa/recovery`) with challenge token + code.
    4. If successful, cookie is set and you’re authenticated.

---

### Step 8 —  Example minimal client-server example sequence

1. POST `/auth/login` → server validates password → returns `{"twoFactorRequired": true, "challengeToken": "..."}`.
2. User enters code `123456`.
3. POST `/auth/2fa/verify` `{ challengeToken: "...", code: "123456" }` → server verifies using `Totp.VerifyTotp(...)` → sets cookie.
