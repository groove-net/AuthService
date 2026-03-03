namespace Auth.Domain;

internal record class UserRegisteredDomainEvent : IDomainEvent
{
    public Guid UserId { get; private set; }
    public String UserEmail { get; private set; }

    public UserRegisteredDomainEvent(Guid userId, String userEmail)
    {
        UserId = userId;
        UserEmail = userEmail;
    }
}
