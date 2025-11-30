namespace Core.Services.Authentication;

public static class AuthOptions
{
  public const int MaxFailedAttempts = 5;
  public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
}