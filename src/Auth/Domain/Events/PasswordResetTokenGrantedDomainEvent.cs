namespace Auth.Domain;

internal record class PasswordResetTokenGrantedDomainEvent : IDomainEvent
{
    public String UserEmail { get; private set; }
    public String Token { get; private set; }

    public PasswordResetTokenGrantedDomainEvent(String userEmail, String token)
    {
        UserEmail = userEmail;
        Token = token;
    }
}
