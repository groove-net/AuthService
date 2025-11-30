using System.Text.Json;

using Microsoft.AspNetCore.DataProtection;

namespace Core.Utilities;

public class EmailTokenGenerator
{
  private readonly IDataProtector _protector;

  public EmailTokenGenerator(IDataProtectionProvider provider)
  {
    _protector = provider.CreateProtector("email-confirmation");
  }

  public string GenerateEmailConfirmationToken(Guid userId)
  {
    var payload = new EmailTokenPayload
    {
      UserId = userId,
      ExpiresAt = DateTime.UtcNow.AddHours(1)
    };

    string json = JsonSerializer.Serialize(payload);
    string protectedData = _protector.Protect(json);

    return Uri.EscapeDataString(protectedData);
  }

  public EmailTokenPayload? ValidateEmailConfirmationToken(string token)
  {
    try
    {
      string protectedData = Uri.UnescapeDataString(token);
      string json = _protector.Unprotect(protectedData);

      var payload = JsonSerializer.Deserialize<EmailTokenPayload>(json);

      if (payload == null || payload.ExpiresAt < DateTime.UtcNow)
        return null;

      return payload;
    }
    catch
    {
      return null;
    }
  }
}

public class EmailTokenPayload
{
  public Guid UserId { get; set; }
  public DateTime ExpiresAt { get; set; }
}