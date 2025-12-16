using FastEndpoints;
using Core.Services.TwoFactor;

namespace WebAPI.Endpoints.auth.twofactor;

public record TwoFactorDisableRequest(Guid user_id);
public class TwoFactorDisableEndPoint(TwoFactorService twoFactorService) : Endpoint<TwoFactorDisableRequest, EmptyResponse>
{
  private readonly TwoFactorService _twoFactorService = twoFactorService;

  public override void Configure()
  {
    Post("/auth/2fa/disable");
    AllowAnonymous();
  }

  public override async Task HandleAsync(TwoFactorDisableRequest req, CancellationToken ct)
  {
    var result = await _twoFactorService.Disable2fa(req.user_id);

    if (!result.IsSuccess || result.Value == null)
    {
      string errorMessage = result.Error == null ? "An Unknown Error Has Occured." : result.Error.Message;
      AddError(errorMessage);
      await Send.ErrorsAsync();
      return;
    }

    await Send.OkAsync();
  }
}