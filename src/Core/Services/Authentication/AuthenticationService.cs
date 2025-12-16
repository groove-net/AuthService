using Core.Data;
using Core.Models;
using Core.Services.Authentication.Errors;
using Core.Utilities;
using Core.Utilities.EmailSender;
using Core.Services.TwoFactor;

using Microsoft.EntityFrameworkCore;

namespace Core.Services.Authentication;

public class AuthenticationService
{
  private readonly AppDbContext _db;
  private readonly PasswordHasher _hasher;
  private readonly EmailTokenGenerator _emailTokens;
  private readonly IEmailSender _email;
  private readonly TwoFactorChallenge _twoFactorChallenge;

  public AuthenticationService(AppDbContext db, PasswordHasher hasher, EmailTokenGenerator emailTokens, IEmailSender email, TwoFactorChallenge twoFactorChallenge)
  {
    _db = db;
    _hasher = hasher;
    _emailTokens = emailTokens;
    _email = email;
    _twoFactorChallenge = twoFactorChallenge;
  }

  public async Task<Result<User, RegisterUserError>> Register(string Username, string Email, string Password)
  {
    User user;

    // Check if username or email exists
    if (await _db.Users.AnyAsync(u => u.Username == Username))
      return Result<User, RegisterUserError>.Fail(RegisterUserError.UsernameExists);

    if (await _db.Users.AnyAsync(u => u.Email == Email))
      return Result<User, RegisterUserError>.Fail(RegisterUserError.EmailExists);

    // Hash password
    var (hash, salt, iterations) = _hasher.HashPassword(Password);

    user = new User
    {
      Username = Username,
      Email = Email,
      PasswordHash = hash,
      PasswordSalt = salt,
      PasswordIterations = iterations,
      EmailConfirmed = false
    };

    _db.Users.Add(user);
    await _db.SaveChangesAsync();

    // Send email confirmation token
    await SendEmailConfirmation(user.Id);

    return Result<User, RegisterUserError>.Success(user);
  }

  public async Task<Result<object, LoginUserError>> Login(string Username, string Password)
  {
    var user = await _db.Users
        .FirstOrDefaultAsync(u => u.Username == Username);

    if (user == null)
      return Result<object, LoginUserError>.Fail(LoginUserError.InvalidCredentials);

    // Check lockout
    if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
    {
      var minutesLeft = (int)(user.LockoutEnd.Value - DateTime.UtcNow).TotalMinutes;
      return Result<object, LoginUserError>.Fail(new LoginUserError("Lockout", $"Account locked. Try again in {minutesLeft} minutes."));
    }

    // Verify password
    bool validPassword = _hasher.VerifyPassword(
        Password,
        user.PasswordSalt,
        user.PasswordIterations,
        user.PasswordHash
    );

    if (!validPassword)
    {
      user.FailedLoginAttempts++;

      // Lock account if too many failures
      if (user.FailedLoginAttempts >= AuthOptions.MaxFailedAttempts)
      {
        user.LockoutEnd = DateTime.UtcNow.Add(AuthOptions.LockoutDuration);
        user.FailedLoginAttempts = 0; // reset counter after locking
      }

      await _db.SaveChangesAsync();
      return Result<object, LoginUserError>.Fail(LoginUserError.InvalidCredentials);
    }

    // Successful login → reset attempts
    user.FailedLoginAttempts = 0;
    user.LockoutEnd = null;
    await _db.SaveChangesAsync();

    // Check if email confirmed
    if (!user.EmailConfirmed)
      return Result<object, LoginUserError>.Fail(LoginUserError.EmailNotConfirmed);

    // --- 2FA step ---
    if (user.TwoFactorEnabled)
    {
      var challengeToken = _twoFactorChallenge.Create(user.Id);
      return Result<object, LoginUserError>.Success(new { ChallengeToken = challengeToken });
    }

    // No 2FA → return full user object
    return Result<object, LoginUserError>
      .Success(new
      {
        id = user.Id,
        username = user.Username,
        email = user.Email
      });
  }

  public async Task<Result<NoResult, SendEmailConfirmationError>> SendEmailConfirmation(Guid userId)
  {
    var user = await _db.Users.FindAsync(userId);
    if (user == null)
      return Result<NoResult, SendEmailConfirmationError>.Fail(SendEmailConfirmationError.InvalidCredentials);

    if (user.EmailConfirmed)
      return Result<NoResult, SendEmailConfirmationError>.Fail(SendEmailConfirmationError.EmailAlreadyConfirmed);

    string token = _emailTokens.GenerateEmailConfirmationToken(user.Id);

    string confirmUrl = $"https://yourapp.com/auth/confirm-email?token={token}";

    Console.WriteLine("EMAIL CONFIRM LINK:");
    Console.WriteLine(confirmUrl);
    await _email.SendEmailAsync(
        user.Email,
        "Welcome!",
        $"Thanks for registering! Here is your EMAIL CONFIRM LINK: {confirmUrl}");

    return Result<NoResult, SendEmailConfirmationError>.Success(new NoResult());
  }

  public async Task<Result<NoResult, ConfirmEmailError>> ConfirmEmail(string token)
  {
    var payload = _emailTokens.ValidateEmailConfirmationToken(token);

    if (payload == null)
      return Result<NoResult, ConfirmEmailError>.Fail(ConfirmEmailError.InvalidToken);

    var user = await _db.Users.FindAsync(payload.UserId);
    if (user == null)
      return Result<NoResult, ConfirmEmailError>.Fail(ConfirmEmailError.UserNotFound);

    if (user.EmailConfirmed)
      return Result<NoResult, ConfirmEmailError>.Fail(ConfirmEmailError.EmailAlreadyConfirmed);

    user.EmailConfirmed = true;
    await _db.SaveChangesAsync();

    return Result<NoResult, ConfirmEmailError>.Success(new NoResult());
  }
}