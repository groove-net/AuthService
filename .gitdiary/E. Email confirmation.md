## 4. Email confirmation

Now we move into email confirmation, which is a core part of secure user onboarding.

This step introduces secure token generation, token signing, and the confirmation flow, all implemented *manually* but using ASP.NET's built-in cryptography so it’s production-safe. In this section, we will build:

1. A secure email confirmation token
2. A `/auth/send-confirmation` endpoint
3. A `/auth/confirm-email` endpoint
4. Token signing using ASP.NET’s Data Protection API
5. Prevent login for unconfirmed users

This is exactly how ASP.NET Identity works under the hood—just much clearer.

### Step 1 — Add `EmailConfirmed` (already done)

Your `User` model already has:

```csharp
public bool EmailConfirmed { get; set; }
```

We’re going to enforce this during login.

### Step 2 — Add Data Protection for Signing Tokens

In your AuthPlayground **class library**, install the package:

```bash
dotnet add src/AuthPlayground package Microsoft.AspNetCore.DataProtection --version 8.0
```

Add this to `AuthPlaygroundServiceCollectionExtensions.cs`:

```csharp
services.AddDataProtection();
```

We’ll inject `IDataProtectionProvider` into our token service.

### Step 3 — Create an `EmailTokenService`

This service generates and validates email confirmation tokens.

Requirements:

- Token must be impossible to forge
- Must expire (e.g., 1 hour)
- Should include the user ID inside the payload
- Should be URL-safe

We use:

- **IDataProtector** for encryption + signing
- **Token payload** containing `UserId`, `ExpiresAt`

---

Below the service is defined:

```csharp
using System.Text.Json;

using Microsoft.AspNetCore.DataProtection;

namespace AuthPlayground.Utilities;

public class EmailTokenGenerator
{
  private readonly IDataProtector _protector;

  public EmailTokenGenerator(IDataProtectionProvider provider)
  {
    _protector = provider.CreateProtector("email-confirmation");
  }

  public string GenerateEmailConfirmationToken(Guid userId)
  {
    var payload = new EmailTokenPayload
    {
      UserId = userId,
      ExpiresAt = DateTime.UtcNow.AddHours(1)
    };

    string json = JsonSerializer.Serialize(payload);
    string protectedData = _protector.Protect(json);

    return Uri.EscapeDataString(protectedData);
  }

  public EmailTokenPayload? ValidateEmailConfirmationToken(string token)
  {
    try
    {
      string protectedData = Uri.UnescapeDataString(token);
      string json = _protector.Unprotect(protectedData);

      var payload = JsonSerializer.Deserialize<EmailTokenPayload>(json);

      if (payload == null || payload.ExpiresAt < DateTime.UtcNow)
        return null;

      return payload;
    }
    catch
    {
      return null;
    }
  }
}

public class EmailTokenPayload
{
  public Guid UserId { get; set; }
  public DateTime ExpiresAt { get; set; }
}

```

💡 DataProtection already handles:

- Encryption
- Signing
- Key rotation
- Secure storage on disk

No JWT, no custom crypto — this is safe.

Dependency injection:

```csharp
services.AddScoped<EmailTokenGenerator>();
```

### Step 4 — Send Email Confirmation Errors

```csharp
using AuthPlayground.Models;

namespace AuthPlayground.Services.Authentication.Errors;

public record SendEmailConfirmationError : Error
{
  public SendEmailConfirmationError(string code, string message)
      : base(code, message) { }

  public static readonly SendEmailConfirmationError InvalidCredentials =
      new("InvalidCredentials", "Invalid username");
  public static readonly SendEmailConfirmationError EmailAlreadyConfirmed =
      new("EmailAlreadyConfirmed", "Email already confirmed");
}

```

### Step 4 — Send Email Confirmation Method

(For now, we won’t send a real email; we’ll just log or return the link.)

Constructor inject the `EmailTokenGenerator` utility and add the `SendEmailConirmation()` method.

```csharp
using AuthPlayground.Data;
using AuthPlayground.Models;
using AuthPlayground.Services.Authentication.Errors;
using AuthPlayground.Utilities;

using Microsoft.EntityFrameworkCore;

namespace AuthPlayground.Services.Authentication;

public class AuthenticationService
{
  // ...
  private readonly EmailTokenGenerator _emailTokens;

  public AuthenticationService(AppDbContext db, PasswordHasher hasher, EmailTokenGenerator emailTokens)
  {
    //...
    _emailTokens = emailTokens;
  }
  
  // ...
  
  public async Task<Result<NoResult, SendEmailConfirmationError>> SendEmailConfirmation(Guid userId)
  {
    var user = await _db.Users.FindAsync(userId);
    if (user == null)
      return Result<NoResult, SendEmailConfirmationError>.Fail(SendEmailConfirmationError.InvalidCredentials);

    if (user.EmailConfirmed)
      return Result<NoResult, SendEmailConfirmationError>.Fail(SendEmailConfirmationError.EmailAlreadyConfirmed);

    string token = _emailTokens.GenerateEmailConfirmationToken(user.Id);

    string confirmUrl = $"https://yourapp.com/auth/confirm-email?token={token}";

    // TODO: send via email instead
    Console.WriteLine("EMAIL CONFIRM LINK:");
    Console.WriteLine(confirmUrl);

    return Result<NoResult, SendEmailConfirmationError>.Success(new NoResult());
  }
}

```

### **Step 3 — Implement an email sender utility**

1. **Create an email sender interface (in the class library)**
    
    This allows the host to inject configuration and the library to stay framework-agnostic.
    
    ```csharp
    namespace Authplayground.Utilities.EmailSender;
    
    public interface IEmailSender
    {
        Task SendEmailAsync(string to, string subject, string body);
    }
    ```
    

---

1. **Implement the email sender (in the class library)**
    
    Example using SMTP:
    
    ```csharp
    using System.Net;
    using System.Net.Mail;
    
    namespace Authplayground.Utilities.EmailSender;
    
    public class SmtpEmailSender : IEmailSender
    {
        private readonly SmtpOptions _options;
    
        public SmtpEmailSender(SmtpOptions options)
        {
            _options = options;
        }
    
        public async Task SendEmailAsync(string to, string subject, string body)
        {
            using var client = new SmtpClient(_options.Host, _options.Port)
            {
                Credentials = new NetworkCredential(_options.Username, _options.Password),
                EnableSsl = _options.EnableSsl
            };
    
            var mail = new MailMessage(_options.From, to, subject, body);
    
            await client.SendMailAsync(mail);
        }
    }
    ```
    
    Add a simple options class:
    
    ```csharp
    namespace Authplayground.Utilities.EmailSender;
    
    public class SmtpOptions
    {
        public string Host { get; set; } = "";
        public int Port { get; set; }
        public string From { get; set; } = "";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public bool EnableSsl { get; set; }
    }
    ```
    
    ### **`Host`**
    
    The SMTP server address of your email provider.
    
    Examples:
    
    - **Gmail:** `smtp.gmail.com`
    - **Outlook / Office 365:** `smtp.office365.com`
    - **ProtonMail Bridge:** `127.0.0.1`
    - **Your own mail server:** Something like `mail.yourdomain.com`
    
    ---
    
    ### **`Port`**
    
    The SMTP port, depending on whether SSL or STARTTLS is used.
    
    Common values:
    
    | Provider | Port | Encryption |
    | --- | --- | --- |
    | Gmail | **587** | STARTTLS |
    | Gmail | **465** | SSL |
    | Office 365 | **587** | STARTTLS |
    | Custom servers | **25** | No encryption (rare) |
    | Custom servers | **465** | SSL |
    
    If you're unsure, 587 is the safest default for modern servers.
    
    ---
    
    ### **`From`**
    
    The email address you want the email to appear from.
    
    Examples:
    
    - `"no-reply@yourdomain.com"`
    - `"support@myapp.com"`
    
    This usually must match the username for the SMTP server unless your domain is configured for relaying.
    
    ---
    
    ### **`Username`**
    
    The username used to authenticate with the SMTP server.
    
    Commonly:
    
    - Your full email address
        
        e.g. `"no-reply@yourdomain.com"`
        
    
    ---
    
    ### **`Password`**
    
    The SMTP password used to authenticate.
    
    How you setup the **SMTP password** depends entirely on the email provider you use. Almost no major provider allows you to use your *actual account password* — you must create an **App Password** or **SMTP-specific password**.
    
    Below is exactly how to set it up depending on your provider:
    
    **If you use Gmail**
    
    Google **blocks SMTP without an App Password** unless:
    
    - You have 2FA enabled
    - You create an **App Password**
    
    **Steps:**
    
    1. Go to [**https://myaccount.google.com/**](https://myaccount.google.com/)
    2. Navigate to **Security**
    3. Enable **2-Step Verification** (required)
    4. Then go to https://myaccount.google.com/apppasswords
    5. Create a new app specific password after specifying an App name.
    6. Google gives you a **16-character password**
    
    Use that for `SmtpOptions.Password`.
    
    **If you use Outlook / Office 365**
    
    Microsoft also requires an App Password **if you have MFA enabled**.
    
    **Steps for Office 365 / Outlook.com:**
    
    1. Go to [**https://account.microsoft.com/security**](https://account.microsoft.com/security)
    2. Enable **Two-step verification**
    3. Open **App passwords**
    4. Generate a new **App Password**
    
    That password is your SMTP password.
    
    ---
    
    **If you use a custom domain email (e.g., Namecheap, GoDaddy, cPanel)**
    
    Most custom hosting environments let you create SMTP accounts.
    
    **Steps (generic cPanel example):**
    
    1. Log into your hosting control panel (cPanel, Plesk, etc.)
    2. Go to **Email Accounts**
    3. Create a new email address like:
        
        `no-reply@yourdomain.com`
        
    4. Set a password → **this IS your SMTP password**
    5. Under "Connect Devices" you will see:
        - SMTP Host
        - SMTP Port
        - SSL/TLS settings
        - Your SMTP password
    
    **If you use a transactional email provider**
    
    These generate SMTP tokens, not passwords:
    
    **SendGrid:**
    
    1. Go to **Settings → API Keys**
    2. Create a key with **Mail Send → Full Access**
    3. Use the API key as the SMTP password
        
        Host: `smtp.sendgrid.net`
        
        Username: `apikey`
        
    
    **Mailgun:**
    
    1. Go to **Domain Settings**
    2. Find the SMTP credentials
    3. Copy SMTP password
    
    **Postmark:**
    
    1. Go to **Servers → Credentials**
    2. Copy the SMTP Token
    
    **⚠️ DO NOT store the password directly in your class library. Store it as a secret.**
    
    ---
    
    ### **`EnableSsl`**
    
    Whether SSL encryption is used. Typically `true`.
    

---

1. **Add an extension method (in the class library)**
    
    This makes DI integration easy for any host application.
    
    ```csharp
    using Microsoft.Extensions.DependencyInjection;
    
    public static class EmailServiceExtensions
    {
        public static IServiceCollection AddEmailSender(
            this IServiceCollection services,
            Action<SmtpOptions> configure)
        {
            var opts = new SmtpOptions();
            configure(opts);
    
            services.AddSingleton(opts);
            services.AddSingleton<IEmailSender, SmtpEmailSender>();
    
            return services;
        }
    }
    ```
    

---

1. **Use it in any constructor-injected service:**
    
    ```csharp
    public class AuthenticationService
    {
    		//...
        private readonly IEmailSender _email;
    
        public AuthenticationService(IEmailSender email)
        {
            _email = email;
        }
    
    		//...
        public async Task SendEmailConfirmationAsync(string email)
        {
            await _email.SendEmailAsync(
                email,
                "Welcome!",
                "Thanks for registering!"
            );
        }
    }
    
    ```
    

### **Step 3 — Implement the send confirmation endpoint on the host**

Implement a minimal`POST /auth/send-confirmation` endpoint in the host Web API app:

```csharp
// ./Endpoints/auth/send-confirmation.cs

using FastEndpoints;
using AuthPlayground.Services.Authentication;

namespace WebAPI.Endpoints.auth;

public record SendConfirmationRequest(Guid userId);
public class SendConfirmationEndPoint(AuthenticationService authenticationService) : Endpoint<SendConfirmationRequest, EmptyResponse>
{
  private readonly AuthenticationService _authenticationService = authenticationService;

  public override void Configure()
  {
    Post("/auth/send-confirmation");
    AllowAnonymous();
  }

  public override async Task HandleAsync(SendConfirmationRequest req, CancellationToken ct)
  {
    var result = await _authenticationService.SendEmailConfirmation(req.userId);

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

```

### Step 4 — Confirm Email Errors

```csharp

using AuthPlayground.Models;

namespace AuthPlayground.Services.Authentication.Errors;

public record ConfirmEmailError : Error
{
  public ConfirmEmailError(string code, string message)
      : base(code, message) { }

  public static readonly ConfirmEmailError InvalidToken =
      new("InvalidToken", "Invalid username");
  public static readonly ConfirmEmailError EmailAlreadyConfirmed =
      new("EmailAlreadyConfirmed", "Email already confirmed");
  public static readonly ConfirmEmailError UserNotFound =
      new("UserNotFound", "User not found");
}
```

### Step 4 — Confirm Email Method

```csharp
public async Task<Result<NoResult, ConfirmEmailError>> ConfirmEmail(string token)
{
  var payload = _emailTokens.ValidateEmailConfirmationToken(token);

  if (payload == null)
    return Result<NoResult, ConfirmEmailError>.Fail(ConfirmEmailError.InvalidToken);

  var user = await _db.Users.FindAsync(payload.UserId);
  if (user == null)
    return Result<NoResult, ConfirmEmailError>.Fail(ConfirmEmailError.UserNotFound);

  if (user.EmailConfirmed)
    return Result<NoResult, ConfirmEmailError>.Fail(ConfirmEmailError.EmailAlreadyConfirmed);

  user.EmailConfirmed = true;
  await _db.SaveChangesAsync();

  return Result<NoResult, ConfirmEmailError>.Success(new NoResult());
}
```

### Step 5 — The `POST /auth/confirm-email` Endpoint

This endpoint validates token → sets `EmailConfirmed=true`.

```csharp
using FastEndpoints;
using AuthPlayground.Services.Authentication;

namespace WebAPI.Endpoints.auth;

public record ConfirmEmailRequest(string token);
public class ConfirmEmailEndPoint(AuthenticationService authenticationService) : Endpoint<ConfirmEmailRequest, EmptyResponse>
{
  private readonly AuthenticationService _authenticationService = authenticationService;

  public override void Configure()
  {
    Post("/auth/confirm-email");
    AllowAnonymous();
  }

  public override async Task HandleAsync(ConfirmEmailRequest req, CancellationToken ct)
  {
    var result = await _authenticationService.ConfirmEmail(req.token);

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

```

### Step 6 — Send Email Confirmation During Registration

Modify your register method:

Add this **BEFORE the success return at the end**:

```csharp
    // Send email confirmation token    
    await SendEmailConfirmation(user.Id);
```

### Step 6 — Prevent Login Before Email Confirmation (Optional)

Depending on business requirement you may decide to disallowing login until email confirmation. To implement this we must modify your login method:

Add this check **AFTER verifying the password and resetting the failed attempts**:

```csharp
    // Check if email confirmed
    if (!user.EmailConfirmed)
      return Result<User, LoginUserError>.Fail(LoginUserError.EmailNotConfirmed);
    
    // TODO: 2FA

```

This is exactly how production systems work.

### 🧪 **Testing**

1. Register
    
    You get a user with `EmailConfirmed = false`.
    
2. Call POST `/auth/send-confirmation`
    
    The console prints the link.
    
3. Call POST `/auth/confirm-email`. 
    
    `GET /auth/confirm-email?token=...`
    
    Response:
    
    ```
    Email confirmed successfully!
    ```
    
4. Try logging in again
    
    Now it works!
    

---

### 🎉 You now have:

✔ A secure, cryptographically signed email confirmation token

✔ Prevented login before email verification

✔ A confirmation endpoint

✔ Signed/validated tokens using Data Protection API

✔ A flexible, extendable foundation for other tokens (password reset, 2FA, etc.)

You're now operating at **IdentityServer lite** level — but with full understanding.
