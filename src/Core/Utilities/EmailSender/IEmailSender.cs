namespace Core.Utilities.EmailSender;

public interface IEmailSender
{
  Task SendEmailAsync(string to, string subject, string body);
}