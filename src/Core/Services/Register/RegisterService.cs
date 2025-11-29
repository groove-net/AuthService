using Core.Data;
using Core.Models;
using Core.Services.Register.Errors;
using Core.Utilities;

using Microsoft.EntityFrameworkCore;

namespace Core.Services.Register;

public class RegisterService
{
  private readonly AppDbContext _db;
  private readonly PasswordHasher _hasher;

  public RegisterService(AppDbContext db, PasswordHasher hasher)
  {
    _db = db;
    _hasher = hasher;
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

    // TODO: send email confirmation token

    return Result<User, RegisterUserError>.Success(user);
  }
}