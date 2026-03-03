using Auth.Domain;

namespace Auth.Application;

internal class PasswordResetTokenGrantedDomainEventHandler : IDomainEventHandler<PasswordResetTokenGrantedDomainEvent>
{
    private readonly IUserRepository _userRepository;
    private readonly IEmailSender _emailSender;
    private readonly IConfirmationTokenGenerator _confirmationTokenGenerator;

    public PasswordResetTokenGrantedDomainEventHandler(
        IUserRepository userRepository,
        IEmailSender emailSender,
        IConfirmationTokenGenerator confirmationTokenGenerator)
    {
        _userRepository = userRepository;
        _emailSender = emailSender;
        _confirmationTokenGenerator = confirmationTokenGenerator;
    }

    public async Task Handle(PasswordResetTokenGrantedDomainEvent domainEvent, CancellationToken ct)
    {
        // Send Email Confirmation
        await _emailSender.SendPasswordResetEmailAsync(domainEvent.UserEmail, domainEvent.Token);
    }
}
