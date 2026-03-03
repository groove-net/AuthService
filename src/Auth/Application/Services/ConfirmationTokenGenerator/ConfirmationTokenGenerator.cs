using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Auth.Application;

internal class ConfirmationTokenGenerator : IConfirmationTokenGenerator
{
    private readonly IDataProtector _protector;

    public ConfirmationTokenGenerator(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("email-confirmation");
    }

    public String GenerateConfirmationToken(Guid userId, String userEmail)
    {
        var payload = new IConfirmationTokenGenerator.Payload
        {
            UserId = userId,
            UserEmail = userEmail,
            ExpiresAt = DateTime.UtcNow.AddHours(1)
        };

        String json = JsonSerializer.Serialize(payload);
        String protectedData = _protector.Protect(json);

        return Uri.EscapeDataString(protectedData);
    }

    public IConfirmationTokenGenerator.Payload? ValidateConfirmationToken(String token)
    {
        try
        {
            String protectedData = Uri.UnescapeDataString(token);
            String json = _protector.Unprotect(protectedData);

            var payload = JsonSerializer.Deserialize<IConfirmationTokenGenerator.Payload>(json);

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
