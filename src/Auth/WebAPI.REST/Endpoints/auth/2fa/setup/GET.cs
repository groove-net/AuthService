using FastEndpoints;
using Auth;

namespace WebAPI.REST.Endpoints.auth.twofactor;

public class TwoFactorSetupEndPoint : Endpoint<TwoFactorSetupEndPoint.Req, object>
{
    public override void Configure()
    {
        Get("/auth/2fa/setup");
        AllowAnonymous();
    }

    public record class Req(Guid userId);
    public override async Task HandleAsync(TwoFactorSetupEndPoint.Req req, CancellationToken ct)
    {
        var result = await AuthComponent.GetTwoFactorSetup("AppName", req.userId);

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
