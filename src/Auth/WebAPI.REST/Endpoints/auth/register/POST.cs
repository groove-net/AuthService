using FastEndpoints;
using Auth;

namespace WebAPI.REST.Endpoints.auth;

public class RegisterEndpoint : Endpoint<RegisterEndpoint.Req, object>
{
    public override void Configure()
    {
        Post("/auth/register");
        AllowAnonymous();
    }

    public record class Req(string username, string email, string password);
    public override async Task HandleAsync(RegisterEndpoint.Req req, CancellationToken ct)
    {
        var result = await AuthComponent.RegisterUser(req.username, req.email, req.password);

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
