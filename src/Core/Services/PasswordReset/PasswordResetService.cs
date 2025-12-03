using Core.Data;
using Core.Models;
using Core.Services.PasswordReset.Errors;
using Core.Utilities;
using Core.Utilities.EmailSender;

using Microsoft.EntityFrameworkCore;
namespace Core.Services.PasswordReset;

public class PasswordResetService
{
  private readonly AppDbContext _db;
  private readonly PasswordHasher _hasher;
  private readonly IEmailSender _email;
  private readonly TimeSpan _tokenTtl = TimeSpan.FromHours(1); // adjust as needed

  public PasswordResetService(AppDbContext db, PasswordHasher hasher, IEmailSender email)
  {
    _db = db;
    _hasher = hasher;
    _email = email;
  }

  // Create a token and persist its hash
  public async Task<Result<NoResult, CreatePasswordResetTokenForEmailError>> CreatePasswordResetTokenForEmailAsync(string email)
  {
    var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user == null)
      return Result<NoResult, CreatePasswordResetTokenForEmailError>.Fail(CreatePasswordResetTokenForEmailError.UserNotFound);

    string tokenString;
    byte[] tokenBytes;
    byte[] tokenHash;
    try
    {
      (tokenString, tokenBytes) = TokenUtils.CreateRandomToken();
      tokenHash = TokenUtils.Sha256(tokenBytes);
    }
    catch
    {
      throw new Exception("Failed to create password reset token");
    }

    var pr = new PasswordResetToken
    {
      UserId = user.Id,
      TokenHash = tokenHash,
      ExpiresAt = DateTime.UtcNow.Add(_tokenTtl),
      Used = false
    };

    _db.PasswordResetTokens.Add(pr);
    await _db.SaveChangesAsync();

    // Compose link. In production, use your real domain and email service.
    string resetUrl = $"https://yourapp.com/auth/reset-password?token={Uri.EscapeDataString(tokenString)}";

    // TODO: Send email with the resetUrl. For dev, log it:
    Console.WriteLine("PASSWORD RESET LINK:");
    Console.WriteLine(resetUrl);
    await _email.SendEmailAsync(
        user.Email,
        "Password Reset!",
        $"Thanks for registering! Here is your PASSWORD RESET LINK: {resetUrl}");

    return Result<NoResult, CreatePasswordResetTokenForEmailError>.Success(new NoResult());
  }

  // Validate token: returns User if valid, and marks token as used
  public async Task<Result<NoResult, ValidateAndConsumeTokenError>> ValidateAndConsumeTokenAsync(string tokenString, string newPassword)
  {
    // Validate password strength here (min length, complexity)
    if (newPassword.Length < 8)
      return Result<NoResult, ValidateAndConsumeTokenError>.Fail(ValidateAndConsumeTokenError.PasswordWeak);

    byte[] tokenHash;
    try
    {
      tokenHash = TokenUtils.Sha256FromTokenString(tokenString);
    }
    catch
    {
      throw new Exception("Failed to hash password reset token");
    }

    var tokenEntry = await _db.PasswordResetTokens
        .Include(t => t.User)
        .Where(t => !t.Used && t.ExpiresAt > DateTime.UtcNow)
        .FirstOrDefaultAsync(t => t.TokenHash.SequenceEqual(tokenHash));

    if (tokenEntry == null || tokenEntry.User == null)
      return Result<NoResult, ValidateAndConsumeTokenError>.Fail(ValidateAndConsumeTokenError.InvalidToken);

    // Mark used (single-use)
    tokenEntry.Used = true;

    // Hash new password
    var (hash, salt, iterations) = _hasher.HashPassword(newPassword);

    tokenEntry.User.PasswordHash = hash;
    tokenEntry.User.PasswordSalt = salt;
    tokenEntry.User.PasswordIterations = iterations;
    tokenEntry.User.UpdatedAt = DateTime.UtcNow;

    // Optionally: revoke active sessions, refresh tokens, etc.
    // Example: sign out user from cookie if you store sessions server-side
    // Or increment a "SecurityStamp" to invalidate server session data

    await _db.SaveChangesAsync();

    return Result<NoResult, ValidateAndConsumeTokenError>.Success(new NoResult());
  }

  // Optional: prune expired tokens periodically
  public async Task PruneExpiredAsync()
  {
    var expired = _db.PasswordResetTokens
        .Where(t => !t.Used && t.ExpiresAt <= DateTime.UtcNow);

    _db.PasswordResetTokens.RemoveRange(expired);
    await _db.SaveChangesAsync();
  }
}