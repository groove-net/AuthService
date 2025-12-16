using FastEndpoints;
using Core.Services.TwoFactor;

namespace WebAPI.Endpoints.auth.twofactor;

public record TwoFactorRecoveryRequest(string challenge_token, string recovery_code);
public class TwoFactorRecoveryEndPoint(TwoFactorService twoFactorService) : Endpoint<TwoFactorRecoveryRequest, object>
{
  private readonly TwoFactorService _twoFactorService = twoFactorService;

  public override void Configure()
  {
    Post("/auth/2fa/recovery");
    AllowAnonymous();
  }

  public override async Task HandleAsync(TwoFactorRecoveryRequest req, CancellationToken ct)
  {
    var result = await _twoFactorService.UseRecoveryCode(req.challenge_token, req.recovery_code);

    if (!result.IsSuccess || result.Value == null)
    {
      string errorMessage = result.Error == null ? "An Unknown Error Has Occured." : result.Error.Message;
      AddError(errorMessage);
      await Send.ErrorsAsync();
      return;
    }

    await Send.OkAsync(result.Value);
  }
}