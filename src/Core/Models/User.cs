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

  // Lockout
  public int FailedLoginAttempts { get; set; }
  public DateTime? LockoutEnd { get; set; }

  // SecurityStamp
  public Guid SecurityStamp { get; set; } = Guid.NewGuid();

  // 2FA
  public bool TwoFactorEnabled { get; set; } = false;
  public string? TwoFactorSecret { get; set; } // Store secret as Base32 string (OtpNet uses Base32)
  public string? RecoveryCodesHashJson { get; set; } // Store recovery codes hashed (comma-separated hex or another table). Example as JSON string:
  public string? PendingTwoFactorSecret { get; set; }
  public long? LastTotpStepUsed { get; set; }

  // Timestamps
  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
  public DateTime? UpdatedAt { get; set; }
}