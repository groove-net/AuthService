using System.Net;
using System.Net.Mail;

namespace Core.Utilities.EmailSender;

public class SmtpEmailSender : IEmailSender
{
  private readonly SmtpOptions _options;

  public SmtpEmailSender(SmtpOptions options)
  {
    _options = options;
  }

  public async Task SendEmailAsync(string to, string subject, string body)
  {
    using var client = new SmtpClient(_options.Host, _options.Port)
    {
      Credentials = new NetworkCredential(_options.Username, _options.Password),
      EnableSsl = _options.EnableSsl
    };

    var mail = new MailMessage(_options.From, to, subject, body);

    await client.SendMailAsync(mail);
  }
}