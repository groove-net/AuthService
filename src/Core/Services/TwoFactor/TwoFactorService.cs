using Core.Data;
using Core.Models;
using Core.Utilities;

using Microsoft.Extensions.Logging;

namespace Core.Services.TwoFactor;

public class TwoFactorService(
  ILogger<TwoFactorService> logger,
  AppDbContext db,
  PasswordHasher hasher,
  TwoFactorUtils twoFactorUtils,
  TwoFactorChallenge twoFactorChallenge)
{
  private readonly AppDbContext _db = db;
  private readonly PasswordHasher _hasher = hasher;
  private readonly TwoFactorUtils _twoFactorUtils = twoFactorUtils;
  private readonly TwoFactorChallenge _twoFactorChallenge = twoFactorChallenge;
  private readonly ILogger<TwoFactorService> _logger = logger;

  // 1) Generate a secret + provisioning QR (user must be authenticated)
  public record Get2faSetupResult
  {
    public string ProvisioningUri { get; set; } = default!;
    public string QrCodeDataUrl { get; set; } = default!;
    public string Secret { get; set; } = default!;
  }
  public async Task<Result<Get2faSetupResult, Error>> Get2faSetup(Guid userId)
  {
    if (userId == Guid.Empty)
      return Result<Get2faSetupResult, Error>
        .Fail(TwoFactorErrors.EmptyUserId);

    var user = await _db.Users.FindAsync(userId);
    if (user == null)
      return Result<Get2faSetupResult, Error>
        .Fail(TwoFactorErrors.UserNotFound);

    // Generate secret and store temporarily in PendingTwoFactorSecret
    var secret = await _twoFactorUtils.BeginTwoFactorEnrollmentAsync(user);

    var issuer = "YourAppName";
    var accountName = $"{issuer}:{user.Email}";

    var uri = _twoFactorUtils.GetProvisioningUri(secret, accountName, issuer);
    var qrDataUrl = Convert.ToBase64String(_twoFactorUtils.GenerateQrCodePng(uri));

    return Result<Get2faSetupResult, Error>
      .Success(new Get2faSetupResult
      {
        ProvisioningUri = uri,
        QrCodeDataUrl = $"data:image/png;base64,{qrDataUrl}",
        Secret = secret
      });
  }

  // 2) Confirm the TOTP code to enable 2FA (user must be authenticated)
  public record Confirm2faResult
  {
    public IReadOnlyList<string> RecoveryCodes { get; set; } = Array.Empty<string>();
  }
  public async Task<Result<Confirm2faResult, Error>> Confirm2fa(Guid userId, string code)
  {
    if (userId == Guid.Empty)
      return Result<Confirm2faResult, Error>
        .Fail(TwoFactorErrors.EmptyUserId);

    if (string.IsNullOrWhiteSpace(code))
      return Result<Confirm2faResult, Error>
        .Fail(TwoFactorErrors.NullOrEmptyCode);

    var user = await _db.Users.FindAsync(userId);
    if (user == null)
      return Result<Confirm2faResult, Error>
          .Fail(TwoFactorErrors.UserNotFound);

    // 2FA already enabled
    if (user.TwoFactorEnabled)
      return Result<Confirm2faResult, Error>
          .Fail(TwoFactorErrors.TwoFactorAlreadyEnabled);

    // Must have begun enrollment first
    if (user.PendingTwoFactorSecret == null)
      return Result<Confirm2faResult, Error>
          .Fail(TwoFactorErrors.TwoFactorNotInitialized);

    // Confirm enrollment (verifies TOTP + enables 2FA)
    var confirmed = await _twoFactorUtils
        .ConfirmTwoFactorEnrollmentAsync(user, code);

    if (!confirmed)
      return Result<Confirm2faResult, Error>
          .Fail(TwoFactorErrors.InvalidCode);

    // Generate recovery codes AFTER successful confirmation
    var recoveryCodes =
        await _twoFactorUtils.GenerateRecoveryCodesAsync(user, count: 10);

    await _db.SaveChangesAsync();

    //  audit log here for account recovery investigations and abuse detection
    _logger.LogInformation("2FA enabled by user={User}", user.Username); // also consider logging user metadata: { ip, userAgent })

    return Result<Confirm2faResult, Error>
      .Success(new Confirm2faResult
      {
        RecoveryCodes = recoveryCodes
      });
  }

  // 3) During login: verify TOTP using challenge token
  // After password verification, if user.TwoFactorEnabled => you should return a challenge token from login endpoint.
  // Here's the verify endpoint that consumes the challenge token and TOTP code, then signs in.
  public record UserResult
  {
    public Guid id { get; set; }
    public string username { get; set; } = default!;
    public string email { get; set; } = default!;
  }
  public async Task<Result<UserResult, Error>> Verify2fa(string challengeToken, string code)
  {

    // Validate code
    if (string.IsNullOrWhiteSpace(code))
      return Result<UserResult, Error>
        .Fail(TwoFactorErrors.NullOrEmptyCode);

    // Validate challenge token
    var challengeResult = _twoFactorChallenge.Validate(challengeToken);
    if (!challengeResult.IsSuccess || challengeResult.Value == null)
      return Result<UserResult, Error>.Fail(challengeResult.Error!);

    // Load user
    var user = await _db.Users.FindAsync(challengeResult.Value.UserId);
    if (user == null)
      return Result<UserResult, Error>
        .Fail(TwoFactorErrors.UserNotFound);

    // Verify TOTP code
    if (Is2faLocked(user))
      return Result<UserResult, Error>
        .Fail(TwoFactorErrors.Locked);

    var ok = await _twoFactorUtils.VerifyTotpAsync(user, code);

    if (!ok)
    {
      Register2faFailure(user);
      await _db.SaveChangesAsync();
      return Result<UserResult, Error>
        .Fail(TwoFactorErrors.InvalidTwoFactorCode);
    }

    Reset2faFailures(user);
    await _db.SaveChangesAsync();

    // Build final result
    return Result<UserResult, Error>
      .Success(new UserResult
      {
        id = user.Id,
        username = user.Username,
        email = user.Email
      });
  }

  // 4) Recovery code usage (during login 2FA phase)
  public async Task<Result<UserResult, Error>> UseRecoveryCode(string challengeToken, string recoveryCode)
  {
    // Validate recovery code
    if (string.IsNullOrWhiteSpace(recoveryCode))
      return Result<UserResult, Error>
        .Fail(TwoFactorErrors.NullOrEmptyRecoveryCode);

    // Validate challenge token
    var challengeResult = _twoFactorChallenge.Validate(challengeToken);
    if (!challengeResult.IsSuccess || challengeResult.Value == null)
      return Result<UserResult, Error>.Fail(challengeResult.Error!);

    // Load user
    var user = await _db.Users.FindAsync(challengeResult.Value.UserId);
    if (user == null)
      return Result<UserResult, Error>
        .Fail(TwoFactorErrors.UserNotFound);

    // Consume recovery code
    if (Is2faLocked(user))
      return Result<UserResult, Error>
        .Fail(TwoFactorErrors.Locked);

    var ok = await _twoFactorUtils.ConsumeRecoveryCodeAsync(user, recoveryCode);

    if (!ok)
    {
      Register2faFailure(user);
      await _db.SaveChangesAsync();
      //  Audit log here for account recovery investigations and abuse detection
      _logger.LogWarning("2FA recovery failure user={User} count={Count}", user.Username, user.TwoFactorFailureCount);
      return Result<UserResult, Error>
        .Fail(TwoFactorErrors.InvalidRecoveryCode);
    }

    Reset2faFailures(user);
    await _db.SaveChangesAsync();

    //  Audit log here for account recovery investigations and abuse detection
    _logger.LogInformation("2FA recovery code used by user={User}", user.Username); // also consider logging user metadata: { ip, userAgent })

    // Build final result
    return Result<UserResult, Error>
      .Success(new UserResult
      {
        id = user.Id,
        username = user.Username,
        email = user.Email
      });
  }

  // 5) Disable2fa
  public async Task<Result<NoResult, Error>> Disable2fa(Guid userId)
  {
    if (userId == Guid.Empty)
      return Result<NoResult, Error>
        .Fail(TwoFactorErrors.EmptyUserId);

    var user = await _db.Users.FindAsync(userId);
    if (user == null)
      return Result<NoResult, Error>
        .Fail(TwoFactorErrors.UserNotFound);

    // Disable and wipe all 2FA state
    await _twoFactorUtils.DisableTwoFactorAsync(user);

    //  audit log here for account recovery investigations and abuse detection
    _logger.LogInformation("2FA disabled by user={User}", user.Username); // also consider logging user metadata: { ip, userAgent })

    return Result<NoResult, Error>.Success(new());
  }

  // helpers: register and reset 2FA failures
  private bool Is2faLocked(User user)
  {
    return user.TwoFactorLockoutUntil != null
        && user.TwoFactorLockoutUntil > DateTime.UtcNow;
  }

  private void Register2faFailure(User user)
  {
    user.TwoFactorFailureCount++;

    if (user.TwoFactorFailureCount >= 5)
    {
      user.TwoFactorLockoutUntil = DateTime.UtcNow.AddMinutes(5);
      user.TwoFactorFailureCount = 0; // reset counter after lockout
    }
  }

  private void Reset2faFailures(User user)
  {
    user.TwoFactorFailureCount = 0;
    user.TwoFactorLockoutUntil = null;
  }

}