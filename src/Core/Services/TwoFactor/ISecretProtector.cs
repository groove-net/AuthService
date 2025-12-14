namespace Core.Services.TwoFactor;

public interface ISecretProtector
{
  string Protect(string plaintext);
  string Unprotect(string ciphertext);
}