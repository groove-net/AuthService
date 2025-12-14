using Core.Models;

namespace Core.Services.PasswordReset.Errors;

public record CreatePasswordResetTokenForEmailError : Error
{
  public CreatePasswordResetTokenForEmailError(string code, string message)
      : base(code, message) { }

  public static readonly CreatePasswordResetTokenForEmailError UserNotFound =
      new("UserNotFound", "A user with the provided email addrees could not be found");

  public static readonly CreatePasswordResetTokenForEmailError TooManyRequests =
      new("TooManyRequests", "Too many password reset requests. Please wait before trying again.");
}