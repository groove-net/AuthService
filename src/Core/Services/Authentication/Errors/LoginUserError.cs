using Core.Models;

namespace Core.Services.Authentication.Errors;

public record LoginUserError : Error
{
  public LoginUserError(string code, string message)
      : base(code, message) { }

  public static readonly LoginUserError InvalidCredentials =
      new("InvalidCredentials", "Invalid username or password");
  public static readonly LoginUserError EmailNotConfirmed =
      new("EmailNotConfirmed", "Email not confirmed");
}