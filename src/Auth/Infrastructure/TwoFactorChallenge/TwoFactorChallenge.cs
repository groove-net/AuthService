using System.Text.Json;

public class TwoFactorChallenge : ITwoFactorChallenge
{
    private readonly ISecretProtector _protector; // for short-lived 2FA challenge tokens

    public TwoFactorChallenge(ISecretProtector protector)
    {
        _protector = protector;
    }

    public string Create(Guid userId)
    {
        var payload = new ITwoFactorChallenge.Payload
        {
            UserId = userId,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5) // short TTL
        };
        var json = JsonSerializer.Serialize(payload);
        return _protector.Protect(json);
    }

    public Result<ITwoFactorChallenge.Payload, Error> Validate(string challengeToken)
    {
        if (string.IsNullOrWhiteSpace(challengeToken))
            return Result<ITwoFactorChallenge.Payload, Error>
              .Fail(new("NullOrEmptyChallengeToken", "Challenge token cannot be null or empty"));

        try
        {
            var json = _protector.Unprotect(challengeToken);
            var payload = JsonSerializer.Deserialize<ITwoFactorChallenge.Payload>(json);
            if (payload == null)
                return Result<ITwoFactorChallenge.Payload, Error>
                  .Fail(new("InvalidChallenge", "Invalid challenge"));

            if (payload.ExpiresAt < DateTime.UtcNow)
                return Result<ITwoFactorChallenge.Payload, Error>
                  .Fail(new("ExpiredChallenge", "Expired challenge"));

            return Result<ITwoFactorChallenge.Payload, Error>.Success(payload);
        }
        catch
        {
            return Result<ITwoFactorChallenge.Payload, Error>
              .Fail(new("InvalidChallenge", "Invalid challenge"));
        }
    }
}
