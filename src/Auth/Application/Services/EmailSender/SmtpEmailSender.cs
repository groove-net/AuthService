using System.Net;
using System.Net.Mail;

namespace Auth.Application;

internal class SmtpEmailSender : IEmailSender
{
    private readonly SmtpOptions _options;

    public SmtpEmailSender()
    {
        _options = new();
    }

    public async Task SendConfirmationEmailAsync(string to, string token)
    {
        // Compose link. In production, use your real domain
        string confirmUrl = $"https://yourapp.com/auth/confirm-email?token={token}";
        Console.WriteLine("EMAIL CONFIRM LINK:");
        Console.WriteLine(confirmUrl);
        string subject = "Welcome!";
        string body = $"Thanks for registering! Here is your EMAIL CONFIRM LINK: {confirmUrl}";

        using var client = new SmtpClient(_options.Host, _options.Port)
        {
            Credentials = new NetworkCredential(_options.Username, _options.Password),
            EnableSsl = _options.EnableSsl
        };

        var mail = new MailMessage(_options.From, to, subject, body);

        await client.SendMailAsync(mail);
    }

    public async Task SendPasswordResetEmailAsync(string to, string token)
    {
        // Compose link. In production, use your real domain
        string resetUrl = $"https://yourapp.com/auth/reset-password?token={token}";
        Console.WriteLine("PASSWORD RESET LINK:");
        Console.WriteLine(resetUrl);
        string subject = "Password Reset!";
        string body = $"Thanks for registering! Here is your PASSWORD RESET LINK: {resetUrl}";

        using var client = new SmtpClient(_options.Host, _options.Port)
        {
            Credentials = new NetworkCredential(_options.Username, _options.Password),
            EnableSsl = _options.EnableSsl
        };

        var mail = new MailMessage(_options.From, to, subject, body);

        await client.SendMailAsync(mail);
    }
}
