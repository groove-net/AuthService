### **Step 1 — Create Login Errors**

```csharp
using AuthPlayground.Models;

namespace AuthPlayground.Services.Authentication.Errors;

public record LoginUserError : Error
{
  public LoginUserError(string code, string message)
      : base(code, message) { }

  public static readonly LoginUserError InvalidCredentials =
      new("InvalidCredentials", "Invalid username or password");
  public static readonly LoginUserError EmailNotConfirmed =
      new("EmailNotConfirmed", "Email not confirmed");
}
```

### **Step 2 — Add Login Method to AuthService**

```csharp
  public async Task<Result<User, LoginUserError>> Login(string Username, string Password)
  {
    var user = await _db.Users
        .FirstOrDefaultAsync(u => u.Username == Username);

    if (user == null)
      return Result<User, LoginUserError>.Fail(LoginUserError.InvalidCredentials);

    // Verify password
    bool validPassword = _hasher.VerifyPassword(
        Password,
        user.PasswordSalt,
        user.PasswordIterations,
        user.PasswordHash
    );

    if (!validPassword)
      return Result<User, LoginUserError>.Fail(LoginUserError.InvalidCredentials);

    // TODO: lockout, email confirmed, 2FA

    return Result<User, LoginUserError>.Success(user);
  }
```

### **Step 3 — Implement the login endpoint on the host**

Implement a minimal`POST /auth/login` endpoint in the host Web API app:

```csharp
// ./Endpoints/auth/login.cs

using FastEndpoints;
using AuthPlayground.Services.Authentication;

namespace WebAPI.Endpoints.auth;

public record LoginRequest(string Username, string Password);
public record LoginResponse(Guid Id, string Username);
public class LoginEndPoint(AuthenticationService authenticationService) : Endpoint<LoginRequest, LoginResponse>
{
  private readonly AuthenticationService _authenticationService = authenticationService;

  public override void Configure()
  {
    Post("/auth/login");
    AllowAnonymous();
  }

  public override async Task HandleAsync(LoginRequest req, CancellationToken ct)
  {
    var result = await _authenticationService.Login(req.Username, req.Password);

    if (!result.IsSuccess || result.Value == null)
    {
      string errorMessage = result.Error == null ? "An Unknown Error Has Occured." : result.Error.Message;
      AddError(errorMessage);
      await Send.ErrorsAsync();
      return;
    }

    await Send.OkAsync(new LoginResponse(result.Value.Id, result.Value.Username));
  }
}

```
