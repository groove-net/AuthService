using FastEndpoints;
using Core.Services.PasswordReset;

namespace WebAPI.Endpoints.auth;

public record RequestPasswordResetRequest(string email);
public class RequestPasswordResetEndpoint(PasswordResetService passwordResetService) : Endpoint<RequestPasswordResetRequest, EmptyResponse>
{
  private readonly PasswordResetService _passwordResetService = passwordResetService;

  public override void Configure()
  {
    Post("/auth/request-password-reset");
    AllowAnonymous();

    // Attach the rate-limiter policy HERE
    Options(opt => opt.RequireRateLimiting("PasswordResetIPPolicy"));
  }

  public override async Task HandleAsync(RequestPasswordResetRequest req, CancellationToken ct)
  {
    var result = await _passwordResetService.CreatePasswordResetTokenForEmailAsync(req.email);

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