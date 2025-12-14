using Core.Data;
using Core.Models;
using Core.Utilities;

using Microsoft.AspNetCore.DataProtection;

using System.Text.Json;

namespace Core.Services.TwoFactor;

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

    return Result<NoResult, UseRecoveryCodeError>.Success(new());
  }

  // helpers: create and unprotect a short-lived 2FA challenge token
  private string CreateChallengeToken(Guid userId)
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