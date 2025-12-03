using System.Security.Cryptography;

namespace Core.Utilities;

public static class TokenUtils
{
  // Create URL-safe token string and return raw bytes too
  public static (string tokenString, byte[] tokenBytes) CreateRandomToken(int size = 32)
  {
    var bytes = RandomNumberGenerator.GetBytes(size);
    var token = Base64UrlEncode(bytes);
    return (token, bytes);
  }

  public static byte[] Sha256(byte[] data)
  {
    using var sha = SHA256.Create();
    return sha.ComputeHash(data);
  }

  public static byte[] Sha256FromTokenString(string tokenString)
  {
    var bytes = Base64UrlDecode(tokenString);
    return Sha256(bytes);
  }

  public static string ToHex(byte[] bytes)
  {
    return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
  }

  private static string Base64UrlEncode(byte[] bytes)
  {
    var base64 = Convert.ToBase64String(bytes);

    // Convert to Base64URL
    return base64
        .Replace("+", "-")
        .Replace("/", "_")
        .TrimEnd('=');
  }

  private static byte[] Base64UrlDecode(string base64Url)
  {
    var padded = base64Url
        .Replace("-", "+")
        .Replace("_", "/");

    // Add missing padding
    switch (padded.Length % 4)
    {
      case 2: padded += "=="; break;
      case 3: padded += "="; break;
    }

    return Convert.FromBase64String(padded);
  }
}