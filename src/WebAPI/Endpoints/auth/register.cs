using FastEndpoints;
using Core.Services.Register;

namespace WebAPI.Endpoints.auth;

public record Request(string Username, string Email, string Password);
public record Response(Guid Id);
public class RegisterEndpoint(RegisterService registerService) : Endpoint<Request, Response>
{
  private readonly RegisterService _registerService = registerService;

  public override void Configure()
  {
    Post("/auth/register");
    AllowAnonymous();
  }

  public override async Task HandleAsync(Request req, CancellationToken ct)
  {
    var result = await _registerService.Register(req.Username, req.Email, req.Password);

    if (!result.IsSuccess || result.Value == null)
    {
      string errorMessage = result.Error == null ? "An Unknown Error Has Occured." : result.Error.Message;
      AddError(errorMessage);
      await Send.ErrorsAsync();
      return;
    }

    await Send.OkAsync(new Response(result.Value.Id));
  }
}