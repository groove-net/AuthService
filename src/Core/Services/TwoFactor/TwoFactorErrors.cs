using Core.Models;

namespace Core.Services.TwoFactor;

internal record TwoFactorErrors : Error
{
  internal TwoFactorErrors(string code, string message)
      : base(code, message) { }

  internal static readonly TwoFactorErrors EmptyUserId =
      new("EmptyUserId", "User Id cannot be empty");

  internal static readonly TwoFactorErrors UserNotFound =
    new("UserNotFound", "User not found");

  internal static readonly TwoFactorErrors InvalidCode =
    new("InvalidCode", "Invalid code");

  internal static readonly TwoFactorErrors Locked =
    new("Locked", "Too many failed attempts");

  internal static readonly TwoFactorErrors ExpiredChallenge =
    new("ExpiredChallenge", "Expired challenge");

  internal static readonly TwoFactorErrors InvalidChallenge =
    new("InvalidChallenge", "Invalid challenge");

  internal static readonly TwoFactorErrors NullOrEmptyCode =
      new("NullOrEmptyCode", "Code cannot be null or empty");

  internal static readonly TwoFactorErrors TwoFactorNotInitialized =
      new("TwoFactorNotInitialized", "2FA setup not initialized");

  internal static readonly TwoFactorErrors TwoFactorAlreadyEnabled =
      new("TwoFactorAlreadyEnabled", "2FA already enabled");

  internal static readonly TwoFactorErrors NullOrEmptyChallengeToken =
      new("NullOrEmptyChallengeToken", "Challenge token cannot be null or empty");

  internal static readonly TwoFactorErrors InvalidTwoFactorCode =
      new("InvalidTwoFactorCode", "Invalid 2FA code");

  internal static readonly TwoFactorErrors NullOrEmptyRecoveryCode =
      new("NullOrEmptyRecoveryCode", "Recovery code cannot be null or empty");

  internal static readonly TwoFactorErrors InvalidRecoveryCode =
      new("InvalidRecoveryCode", "Invalid recovery code");
}