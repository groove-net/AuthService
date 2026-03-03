namespace Auth.Application;

internal interface IEmailSender
{
    Task SendConfirmationEmailAsync(string to, string token);
    Task SendPasswordResetEmailAsync(string to, string token);
}
