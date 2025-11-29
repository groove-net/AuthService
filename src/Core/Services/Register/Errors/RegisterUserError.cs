using Core.Models;

namespace Core.Services.Register.Errors;

public record RegisterUserError : Error
{
  private RegisterUserError(string code, string message)
      : base(code, message) { }

  public static readonly RegisterUserError UsernameExists =
      new("UsernameExists", "The username is already taken.");

  public static readonly RegisterUserError EmailExists =
      new("EmailExists", "The email address is already registered.");

  public static readonly RegisterUserError WeakPassword =
      new("WeakPassword", "The provided password does not meet security requirements.");

  public static readonly RegisterUserError ValidationFailed =
      new("ValidationFailed", "One or more fields are invalid.");
}