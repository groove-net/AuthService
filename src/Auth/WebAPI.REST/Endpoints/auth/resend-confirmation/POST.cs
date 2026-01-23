using FastEndpoints;
using Auth;

namespace WebAPI.REST.Endpoints.auth;

public class ResendConfirmationEndPoint : Endpoint<ResendConfirmationEndPoint.Req, object>
{
    public override void Configure()
    {
        Post("/auth/resend-confirmation");
        AllowAnonymous();
    }

    public record class Req(Guid userId);
    public override async Task HandleAsync(ResendConfirmationEndPoint.Req req, CancellationToken ct)
    {
        var result = await AuthComponent.ResendEmailConfirmation(req.userId);

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
