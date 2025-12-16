using FastEndpoints;
using Core.Services.TwoFactor;

namespace WebAPI.Endpoints.auth.twofactor;

public record TwoFactorSetupRequest(Guid user_id);
public class TwoFactorSetupEndPoint(TwoFactorService twoFactorService) : Endpoint<TwoFactorSetupRequest, TwoFactorService.Get2faSetupResult>
{
  private readonly TwoFactorService _twoFactorService = twoFactorService;

  public override void Configure()
  {
    Get("/auth/2fa/setup");
    AllowAnonymous();
  }

  public override async Task HandleAsync(TwoFactorSetupRequest req, CancellationToken ct)
  {
    var result = await _twoFactorService.Get2faSetup(req.user_id);

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