using FastEndpoints;
using Core.Services.Authentication;

namespace WebAPI.Endpoints.auth;

public record SendConfirmationRequest(Guid userId);
public class SendConfirmationEndPoint(AuthenticationService authenticationService) : Endpoint<SendConfirmationRequest, EmptyResponse>
{
  private readonly AuthenticationService _authenticationService = authenticationService;

  public override void Configure()
  {
    Post("/auth/send-confirmation");
    AllowAnonymous();
  }

  public override async Task HandleAsync(SendConfirmationRequest req, CancellationToken ct)
  {
    var result = await _authenticationService.SendEmailConfirmation(req.userId);

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