using FastEndpoints;
using Auth;

namespace WebAPI.REST.Endpoints.auth;

public class LoginEndpoint : Endpoint<LoginEndpoint.Req, object>
{
    public override void Configure()
    {
        Post("/auth/login");
        AllowAnonymous();
    }

    public record class Req(string username, string password);
    public override async Task HandleAsync(LoginEndpoint.Req req, CancellationToken ct)
    {
        var result = await AuthComponent.Login(req.username, req.password);

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
