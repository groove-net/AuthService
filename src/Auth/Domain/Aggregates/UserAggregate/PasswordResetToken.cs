public class PasswordResetToken : Entity
{
    public Byte[] TokenHash { get; private set; } // SHA256 hash of the token
    public DateTime ExpiresAt { get; private set; }
    public Boolean Used { get; private set; }
    public DateTime CreatedAt { get; private set; }
    private readonly TimeSpan _tokenTtl = TimeSpan.FromHours(1); // adjust as needed

    // navigation
    public User? User { get; private set; }

    public PasswordResetToken(Byte[] tokenHash)
    {
        TokenHash = tokenHash;
        ExpiresAt = DateTime.UtcNow.Add(_tokenTtl);
        Used = false;
        CreatedAt = DateTime.UtcNow;
    }

    public void InvalidateToken()
      => Used = true;
}
