using Core.Models;

namespace Core.Services.Authentication.Errors;

public record SendEmailConfirmationError : Error
{
  public SendEmailConfirmationError(string code, string message)
      : base(code, message) { }

  public static readonly SendEmailConfirmationError InvalidCredentials =
      new("InvalidCredentials", "Invalid username");
  public static readonly SendEmailConfirmationError EmailAlreadyConfirmed =
      new("EmailAlreadyConfirmed", "Email already confirmed");
}