using FastEndpoints;
using Auth;

namespace WebAPI.REST.Endpoints.auth.twofactor;

public class TwoFactorDisableEndPoint : Endpoint<TwoFactorDisableEndPoint.Req, object>
{
    public override void Configure()
    {
        Post("/auth/2fa/disable");
        AllowAnonymous();
    }

    public record class Req(Guid userId);
    public override async Task HandleAsync(TwoFactorDisableEndPoint.Req req, CancellationToken ct)
    {
        var result = await AuthComponent.DisableTwoFactor(req.userId);

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
