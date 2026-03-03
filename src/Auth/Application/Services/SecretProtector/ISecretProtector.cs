namespace Auth.Application;

internal interface ISecretProtector
{
    string Protect(string plaintext);
    string Unprotect(string ciphertext);
}
