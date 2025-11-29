using System.Security.Cryptography;

namespace Core.Utilities;

public class PasswordHasher
{
  private const int SaltSize = 16; // 128-bit
  private const int KeySize = 32;  // 256-bit

  // Choose an iteration count suitable for modern hardware
  private const int Iterations = 150_000;

  public (byte[] hash, byte[] salt, int iterations) HashPassword(string password)
  {
    // Create salt
    byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

    // Derive key
    using var pbkdf2 = new Rfc2898DeriveBytes(
        password,
        salt,
        Iterations,
        HashAlgorithmName.SHA256
    );

    byte[] key = pbkdf2.GetBytes(KeySize);

    return (key, salt, Iterations);
  }

  public bool VerifyPassword(string password, byte[] salt, int iterations, byte[] expectedHash)
  {
    using var pbkdf2 = new Rfc2898DeriveBytes(
        password,
        salt,
        iterations,
        HashAlgorithmName.SHA256
    );

    byte[] computed = pbkdf2.GetBytes(expectedHash.Length);

    return CryptographicOperations.FixedTimeEquals(computed, expectedHash);
  }
}