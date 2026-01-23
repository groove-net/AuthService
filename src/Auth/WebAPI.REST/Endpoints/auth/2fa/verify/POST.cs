using FastEndpoints;
using Auth;

namespace WebAPI.REST.Endpoints.auth.twofactor;

public class TwoFactorVerifyEndPoint : Endpoint<TwoFactorVerifyEndPoint.Req, object>
{
    public override void Configure()
    {
        Post("/auth/2fa/verify");
        AllowAnonymous();
    }

    public record class Req(string challengeToken, string code);
    public override async Task HandleAsync(TwoFactorVerifyEndPoint.Req req, CancellationToken ct)
    {
        var result = await AuthComponent.VerifyTwoFactor(req.challengeToken, req.code);

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
