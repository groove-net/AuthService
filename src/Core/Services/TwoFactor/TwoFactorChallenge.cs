using System.Text.Json;

using Core.Models;

namespace Core.Services.TwoFactor;

public class TwoFactorChallenge(ISecretProtector protector)
{
  private readonly ISecretProtector _protector = protector; // for short-lived 2FA challenge tokens

  public record Payload
  {
    public Guid UserId { get; set; }
    public DateTime ExpiresAt { get; set; }
  }

  public string Create(Guid userId)
  {
    var payload = new Payload
    {
      UserId = userId,
      ExpiresAt = DateTime.UtcNow.AddMinutes(5) // short TTL
    };
    var json = JsonSerializer.Serialize(payload);
    return _protector.Protect(json);
  }

  public Result<Payload, Error> Validate(string challengeToken)
  {
    if (string.IsNullOrWhiteSpace(challengeToken))
      return Result<Payload, Error>
        .Fail(TwoFactorErrors.NullOrEmptyChallengeToken);

    try
    {
      var json = _protector.Unprotect(challengeToken);
      var payload = JsonSerializer.Deserialize<Payload>(json);
      if (payload == null)
        return Result<Payload, Error>
          .Fail(TwoFactorErrors.InvalidChallenge);

      if (payload.ExpiresAt < DateTime.UtcNow)
        return Result<Payload, Error>
          .Fail(TwoFactorErrors.ExpiredChallenge);

      return Result<Payload, Error>.Success(payload);
    }
    catch
    {
      return Result<Payload, Error>
        .Fail(TwoFactorErrors.InvalidChallenge);
    }
  }
}