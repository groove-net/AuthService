using FastEndpoints;
using Auth;

namespace WebAPI.REST.Endpoints.auth;

public class RequestPasswordResetEndpoint : Endpoint<RequestPasswordResetEndpoint.Req, object>
{
    public override void Configure()
    {
        Post("/auth/request-password-reset");
        AllowAnonymous();

        // Attach the rate-limiter policy HERE
        Options(opt => opt.RequireRateLimiting("PasswordResetIPPolicy"));
    }

    public record class Req(string email);
    public override async Task HandleAsync(RequestPasswordResetEndpoint.Req req, CancellationToken ct)
    {
        var result = await AuthComponent.RequestPasswordReset(req.email);

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
