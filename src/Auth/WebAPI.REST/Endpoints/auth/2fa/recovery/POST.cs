using FastEndpoints;
using Auth;

namespace WebAPI.REST.Endpoints.auth.twofactor;

public class TwoFactorRecoveryEndPoint : Endpoint<TwoFactorRecoveryEndPoint.Req, object>
{
    public override void Configure()
    {
        Post("/auth/2fa/recovery");
        AllowAnonymous();
    }

    public record class Req(string challengeToken, string recoveryCode);
    public override async Task HandleAsync(TwoFactorRecoveryEndPoint.Req req, CancellationToken ct)
    {
        var result = await AuthComponent.UseRecoveryCode(req.challengeToken, req.recoveryCode);

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
