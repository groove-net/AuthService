namespace Core.Models;

public class User
{
  public Guid Id { get; set; } = Guid.NewGuid();

  public string Username { get; set; } = default!;
  public string Email { get; set; } = default!;
  public bool EmailConfirmed { get; set; }

  public byte[] PasswordHash { get; set; } = default!;
  public byte[] PasswordSalt { get; set; } = default!;
  public int PasswordIterations { get; set; }

  public int FailedLoginAttempts { get; set; }
  public DateTime? LockoutEnd { get; set; }

  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
  public DateTime? UpdatedAt { get; set; }
}