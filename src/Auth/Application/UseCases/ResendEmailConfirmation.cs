using Auth.Domain;

namespace Auth.Application;

internal class ResendEmailConfirmation
{
    private readonly IUserRepository _userRepository;
    private readonly IEmailSender _emailSender;
    private readonly IConfirmationTokenGenerator _confirmationTokenGenerator;

    public ResendEmailConfirmation(
        IUserRepository userRepository,
        IEmailSender emailSender,
        IConfirmationTokenGenerator confirmationTokenGenerator)
    {
        _userRepository = userRepository;
        _emailSender = emailSender;
        _confirmationTokenGenerator = confirmationTokenGenerator;
    }

    // 3. Handle method
    public async Task<Result<EmptyResult, Error>> Handle(String userEmail)
    {
        var user = await _userRepository.FindByEmailAsync(userEmail);
        if (user is null)
            return Result<EmptyResult, Error>.Fail(new("UserNotFound", "User not found"));

        if (user.EmailConfirmed)
            return Result<EmptyResult, Error>.Fail(new("EmailAlreadyConfirmed", "Email already confirmed"));

        // Send Email Confirmation
        string token = _confirmationTokenGenerator.GenerateConfirmationToken(user.Id, user.Email);
        await _emailSender.SendConfirmationEmailAsync(user.Email, token);

        return Result<EmptyResult, Error>.Success(new EmptyResult());
    }
}
