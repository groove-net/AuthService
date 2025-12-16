using FastEndpoints;
using Core.Services.TwoFactor;

namespace WebAPI.Endpoints.auth.twofactor;

public record TwoFactorVerifyRequest(string challenge_token, string code);
public class TwoFactorVerifyEndPoint(TwoFactorService twoFactorService) : Endpoint<TwoFactorVerifyRequest, object>
{
  private readonly TwoFactorService _twoFactorService = twoFactorService;

  public override void Configure()
  {
    Post("/auth/2fa/verify");
    AllowAnonymous();
  }

  public override async Task HandleAsync(TwoFactorVerifyRequest req, CancellationToken ct)
  {
    var result = await _twoFactorService.Verify2fa(req.challenge_token, req.code);

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