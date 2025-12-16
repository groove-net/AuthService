using FastEndpoints;
using Core.Services.TwoFactor;

namespace WebAPI.Endpoints.auth.twofactor;

public record TwoFactorConfirmRequest(Guid user_id, string code);
public class TwoFactorConfirmEndPoint(TwoFactorService twoFactorService) : Endpoint<TwoFactorConfirmRequest, TwoFactorService.Confirm2faResult>
{
  private readonly TwoFactorService _twoFactorService = twoFactorService;

  public override void Configure()
  {
    Post("/auth/2fa/confirm");
    AllowAnonymous();
  }

  public override async Task HandleAsync(TwoFactorConfirmRequest req, CancellationToken ct)
  {
    var result = await _twoFactorService.Confirm2fa(req.user_id, req.code);

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