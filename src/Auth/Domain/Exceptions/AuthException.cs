namespace Auth.Domain;

/// <summary>
/// Exception type for domain exceptions
/// </summary>
internal class AuthException : Exception
{
    public AuthException()
    { }

    public AuthException(string message)
        : base(message)
    { }

    public AuthException(string message, Exception innerException)
        : base(message, innerException)
    { }
}
