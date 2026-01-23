using System.Security.Cryptography;
using System.Text;

public sealed class AesGcmSecretProtector : ISecretProtector
{
    // Versioning allows future crypto migration
    private const byte Version = 1;

    // AES-GCM parameters (do not change without version bump)
    private const int NonceSizeBytes = 12; // 96-bit
    private const int TagSizeBytes = 16;   // 128-bit

    private readonly byte[] _key;

    // Key must be 16, 24, or 32 bytes (AES-128/192/256)
    public AesGcmSecretProtector(byte[] key)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        if (key.Length is not (16 or 24 or 32))
            throw new ArgumentException("Key must be 16, 24, or 32 bytes", nameof(key));

        _key = key;
    }

    public string Protect(string plaintext)
    {
        if (plaintext == null)
            throw new ArgumentNullException(nameof(plaintext));

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var tag = new byte[TagSizeBytes];
        var ciphertext = new byte[plaintextBytes.Length];

        using var aes = new AesGcm(_key, TagSizeBytes);
        aes.Encrypt(
          nonce,
          plaintextBytes,
          ciphertext,
          tag,
          associatedData: new[] { Version }
        );

        // Payload format:
        // [version][nonce][tag][ciphertext]
        var payload = new byte[
            1 +
            NonceSizeBytes +
            TagSizeBytes +
            ciphertext.Length];

        payload[0] = Version;

        Buffer.BlockCopy(nonce, 0, payload, 1, NonceSizeBytes);
        Buffer.BlockCopy(tag, 0, payload, 1 + NonceSizeBytes, TagSizeBytes);
        Buffer.BlockCopy(
            ciphertext,
            0,
            payload,
            1 + NonceSizeBytes + TagSizeBytes,
            ciphertext.Length);

        return Convert.ToBase64String(payload);
    }

    public string Unprotect(string protectedData)
    {
        if (protectedData == null)
            throw new ArgumentNullException(nameof(protectedData));

        // convert URL-safe Base64 to standard
        protectedData = protectedData.Replace('-', '+').Replace('_', '/');
        switch (protectedData.Length % 4)
        {
            case 2: protectedData += "=="; break;
            case 3: protectedData += "="; break;
        }

        var payload = Convert.FromBase64String(protectedData);

        if (payload.Length < 1 + NonceSizeBytes + TagSizeBytes)
            throw new CryptographicException("Invalid protected payload");

        var version = payload[0];
        if (version != Version)
            throw new CryptographicException("Unsupported secret version");

        var nonce = payload.AsSpan(1, NonceSizeBytes).ToArray();
        var tag = payload.AsSpan(1 + NonceSizeBytes, TagSizeBytes).ToArray();
        var ciphertext = payload
            .AsSpan(1 + NonceSizeBytes + TagSizeBytes)
            .ToArray();

        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(_key, TagSizeBytes);
        aes.Decrypt(
          nonce,
          ciphertext,
          tag,
          plaintext,
          associatedData: new[] { version }
        );

        return Encoding.UTF8.GetString(plaintext);
    }
}
