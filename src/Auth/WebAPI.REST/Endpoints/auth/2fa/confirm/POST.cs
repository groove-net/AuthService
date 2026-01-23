using FastEndpoints;
using Auth;

namespace WebAPI.REST.Endpoints.auth.twofactor;

public class TwoFactorConfirmEndPoint : Endpoint<TwoFactorConfirmEndPoint.Req, object>
{
    public override void Configure()
    {
        Post("/auth/2fa/confirm");
        AllowAnonymous();
    }

    public record class Req(Guid userId, string code);
    public override async Task HandleAsync(TwoFactorConfirmEndPoint.Req req, CancellationToken ct)
    {
        var result = await AuthComponent.ConfirmTwoFactorSetup(req.userId, req.code);

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
