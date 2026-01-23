using FastEndpoints;
using Auth;

namespace WebAPI.REST.Endpoints;

public class ConfirmEmailEndpoint : Endpoint<ConfirmEmailEndpoint.Req, object>
{
    public override void Configure()
    {
        Post("/auth/confirm-email");
        AllowAnonymous();
    }

    public record class Req(String token);
    public override async Task HandleAsync(ConfirmEmailEndpoint.Req req, CancellationToken ct)
    {
        var result = await AuthComponent.ConfirmEmail(req.token);

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
