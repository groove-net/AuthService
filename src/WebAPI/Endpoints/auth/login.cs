using FastEndpoints;
using Core.Services.Authentication;

namespace WebAPI.Endpoints.auth;

public record LoginRequest(string Username, string Password);
public class LoginEndPoint(AuthenticationService authenticationService) : Endpoint<LoginRequest, object>
{
  private readonly AuthenticationService _authenticationService = authenticationService;

  public override void Configure()
  {
    Post("/auth/login");
    AllowAnonymous();
  }

  public override async Task HandleAsync(LoginRequest req, CancellationToken ct)
  {
    var result = await _authenticationService.Login(req.Username, req.Password);

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