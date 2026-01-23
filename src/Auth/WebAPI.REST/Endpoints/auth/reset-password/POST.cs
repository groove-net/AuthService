using FastEndpoints;
using Auth;

namespace WebAPI.REST.Endpoints.auth;

public class ResetPasswordEndpoint : Endpoint<ResetPasswordEndpoint.Req, object>
{
    public override void Configure()
    {
        Post("/auth/reset-password");
        AllowAnonymous();
    }

    public record class Req(string token, string newPassword);
    public override async Task HandleAsync(ResetPasswordEndpoint.Req req, CancellationToken ct)
    {
        var result = await AuthComponent.ResetPassword(req.token, req.newPassword);

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
