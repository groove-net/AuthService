using Core.Models;

namespace Core.Services.Authentication.Errors;

public record ConfirmEmailError : Error
{
  public ConfirmEmailError(string code, string message)
      : base(code, message) { }

  public static readonly ConfirmEmailError InvalidToken =
      new("InvalidToken", "Invalid username");
  public static readonly ConfirmEmailError EmailAlreadyConfirmed =
      new("EmailAlreadyConfirmed", "Email already confirmed");
  public static readonly ConfirmEmailError UserNotFound =
      new("UserNotFound", "User not found");
}