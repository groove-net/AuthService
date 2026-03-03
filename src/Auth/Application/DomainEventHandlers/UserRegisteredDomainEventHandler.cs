using Auth.Domain;

namespace Auth.Application;

internal class UserRegisteredDomainEventHandler : IDomainEventHandler<UserRegisteredDomainEvent>
{
    private readonly IUserRepository _userRepository;
    private readonly IEmailSender _emailSender;
    private readonly IConfirmationTokenGenerator _confirmationTokenGenerator;

    public UserRegisteredDomainEventHandler(
        IUserRepository userRepository,
        IEmailSender emailSender,
        IConfirmationTokenGenerator confirmationTokenGenerator)
    {
        _userRepository = userRepository;
        _emailSender = emailSender;
        _confirmationTokenGenerator = confirmationTokenGenerator;
    }

    public async Task Handle(UserRegisteredDomainEvent domainEvent, CancellationToken ct)
    {
        // Send Email Confirmation
        string token = _confirmationTokenGenerator.GenerateConfirmationToken(domainEvent.UserId, domainEvent.UserEmail);
        await _emailSender.SendConfirmationEmailAsync(domainEvent.UserEmail, token);
    }
}
