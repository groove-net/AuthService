using Core.Models;

namespace Core.Services.PasswordReset.Errors;

public record ValidateAndConsumeTokenError : Error
{
  public ValidateAndConsumeTokenError(string code, string message)
      : base(code, message) { }

  public static readonly ValidateAndConsumeTokenError PasswordWeak =
      new("PasswordWeak", "Password too weak");
  public static readonly ValidateAndConsumeTokenError InvalidToken =
      new("InvalidToken", "Invalid or expired token");
}