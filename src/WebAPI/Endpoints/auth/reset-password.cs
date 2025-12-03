using FastEndpoints;
using Core.Services.PasswordReset;

namespace WebAPI.Endpoints.auth;

public record ResetPasswordRequest(string tokenString, string newPassword);
public class ResetPasswordEndpoint(PasswordResetService passwordResetService) : Endpoint<ResetPasswordRequest, EmptyResponse>
{
  private readonly PasswordResetService _passwordResetService = passwordResetService;

  public override void Configure()
  {
    Post("/auth/reset-password");
    AllowAnonymous();
  }

  public override async Task HandleAsync(ResetPasswordRequest req, CancellationToken ct)
  {
    var result = await _passwordResetService.ValidateAndConsumeTokenAsync(req.tokenString, req.newPassword);

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