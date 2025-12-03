namespace Core.Models;

public class PasswordResetToken
{
  public Guid Id { get; set; } = Guid.NewGuid();
  public Guid UserId { get; set; }
  public byte[] TokenHash { get; set; } = default!; // SHA256 hash of the token
  public DateTime ExpiresAt { get; set; }
  public bool Used { get; set; } = false;
  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

  // navigation
  public User? User { get; set; }
}