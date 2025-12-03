namespace Core.Utilities.EmailSender;

public class SmtpOptions
{
  public string Host { get; set; } = "smtp.gmail.com";
  public int Port { get; set; } = 587;
  public string From { get; set; } = "gabadelemoni@gmail.com";
  public string Username { get; set; } = "gabadelemoni@gmail.com";
  public string Password { get; set; } = "tycl jkav esrb pwha";
  public bool EnableSsl { get; set; } = true;
}