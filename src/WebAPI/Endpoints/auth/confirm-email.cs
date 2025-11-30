using FastEndpoints;
using Core.Services.Authentication;

namespace WebAPI.Endpoints.auth;

public record ConfirmEmailRequest(string token);
public class ConfirmEmailEndPoint(AuthenticationService authenticationService) : Endpoint<ConfirmEmailRequest, EmptyResponse>
{
  private readonly AuthenticationService _authenticationService = authenticationService;

  public override void Configure()
  {
    Post("/auth/confirm-email");
    AllowAnonymous();
  }

  public override async Task HandleAsync(ConfirmEmailRequest req, CancellationToken ct)
  {
    var result = await _authenticationService.ConfirmEmail(req.token);

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