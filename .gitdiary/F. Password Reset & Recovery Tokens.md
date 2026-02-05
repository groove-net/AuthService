Now let’s implement password reset & recovery tokens. I’ll give you a secure, production-style flow that’s still small and easy to understand.

Goals and security rules we’ll follow:

- Tokens are single-use and time-limited.
- Tokens are impossible to guess (cryptographically random).
- We store only a hash of the token in the DB (so a DB leak won’t let attackers use active tokens).
- Responses don’t leak whether an email exists.
- You can enforce rate limits / prune expired tokens.
- We’ll reuse our `PasswordHasher` to write the new password.

Design overview (safe, simple, production-like)

1. Client calls `POST /auth/request-password-reset` with `{ "email": "..." }`.
    - Server generates `rawToken` (cryptographically random), calculates `tokenHash = SHA256(rawToken)`.
    - Server stores `PasswordResetToken { Id, UserId, TokenHash, ExpiresAt, Used=false }` in DB.
    - Server sends email containing a URL with the raw token (e.g. `/auth/reset-password?token=...`) **OR** returns the link in dev mode.
    - Response is a generic message: *"If an account exists, we sent an email."*
2. User follows link and POSTs `POST /auth/reset-password` with `{ "token": "...", "newPassword": "..." }`.
    - Server computes SHA256(token) and looks up a non-used, non-expired DB row with that `TokenHash`.
    - If valid: mark `Used = true`, update user's password (hash using PBKDF2), optionally revoke sessions/refresh tokens.
    - Return success.
    - If invalid: generic failure message.
3. Periodically prune expired tokens from DB.

### Step 0 - Update User Model

```csharp
namespace AuthPlayground.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Username { get; set; } = default!;
    public string Email { get; set; } = default!;
    public bool EmailConfirmed { get; set; }

    public byte[] PasswordHash { get; set; } = default!;
    public byte[] PasswordSalt { get; set; } = default!;
    public int PasswordIterations { get; set; }
    
    public Guid SecurityStamp { get; set; } = Guid.NewGuid();

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }
}
```

```bash
dotnet ef migrations add AddSecurityStamp --project ../AuthPlayground --startup-project .
dotnet ef database update --project ../AuthPlayground --startup-project .
```

### Step 1 — DB model: `PasswordResetToken`

Add this EF model:

```csharp
namespace AuthPlayground.Models;

public class PasswordResetToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public byte[] TokenHash { get; set; } = default!; // SHA256 hash of the token
    public DateTime ExpiresAt { get; set; }
    public bool Used { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // navigation
    public User? User { get; set; }
}
```

Add to `AppDbContext`:

```csharp
public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
```

Run the migration:

```bash
dotnet ef migrations add AddPasswordResetTokens --project ../AuthPlayground --startup-project .
dotnet ef database update --project ../AuthPlayground --startup-project .
```

### Step 2 — Token utilities

Token generation details (server-side)

- Token raw bytes: 32 bytes (`RandomNumberGenerator.GetBytes(32)`).
- Encode to URL-safe string: `WebEncoders.Base64UrlEncode(...)` (in `Microsoft.AspNetCore.WebUtilities`) or manually replace `+`/`/`/`=`. Using WebEncoders is easiest.
- Store `tokenHash = SHA256(rawTokenBytes)` in DB.

Storing the **hash** means if the DB is leaked, attacker cannot use the stored value to reset passwords.

```csharp
using System.Security.Cryptography;

namespace AuthPlayground.Utilities;

public static class TokenUtils
{
  // Create URL-safe token string and return raw bytes too
  public static (string tokenString, byte[] tokenBytes) CreateRandomToken(int size = 32)
  {
    var bytes = RandomNumberGenerator.GetBytes(size);
    var token = Base64UrlEncode(bytes);
    return (token, bytes);
  }

  public static byte[] Sha256(byte[] data)
  {
    using var sha = SHA256.Create();
    return sha.ComputeHash(data);
  }

  public static byte[] Sha256FromTokenString(string tokenString)
  {
    var bytes = Base64UrlDecode(tokenString);
    return Sha256(bytes);
  }

  public static string ToHex(byte[] bytes)
  {
    return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
  }

  private static string Base64UrlEncode(byte[] bytes)
  {
    var base64 = Convert.ToBase64String(bytes);

    // Convert to Base64URL
    return base64
        .Replace("+", "-")
        .Replace("/", "_")
        .TrimEnd('=');
  }

  private static byte[] Base64UrlDecode(string base64Url)
  {
    var padded = base64Url
        .Replace("-", "+")
        .Replace("_", "/");

    // Add missing padding
    switch (padded.Length % 4)
    {
      case 2: padded += "=="; break;
      case 3: padded += "="; break;
    }

    return Convert.FromBase64String(padded);
  }
}

```

(You can also store tokenHash as a hex string if you prefer; above stores a `byte[]`.)

### Step 3 — Create the Password Reset Errors

```csharp
using Core.Models;

namespace Core.Services.PasswordReset.Errors;

public record CreatePasswordResetTokenForEmailError : Error
{
  public CreatePasswordResetTokenForEmailError(string code, string message)
      : base(code, message) { }

  public static readonly CreatePasswordResetTokenForEmailError UserNotFound =
      new("UserNotFound", "A user with the provided email addrees could not be found");
      
  public static readonly CreatePasswordResetTokenForEmailError TooManyRequests =
      new("TooManyRequests", "Too many password reset requests. Please wait before trying again.");
}
```

```csharp
using Core.Models;

namespace Core.Services.PasswordReset.Errors;

public record ValidateAndConsumeTokenError : Error
{
  public ValidateAndConsumeTokenError(string code, string message)
      : base(code, message) { }

  public static readonly ValidateAndConsumeTokenError PasswordWeak =
      new("PasswordWeak", "Password too weak");
  public static readonly ValidateAndConsumeTokenError InvalidToken =
      new("InvalidToken", "Invalid or expired token");
}
```

### Step 3 — Create the Password Reset Service

Create a scoped service to encapsulate token creation/validation/pruning:

```csharp
using AuthPlayground.Data;
using AuthPlayground.Models;
using AuthPlayground.Services.PasswordReset.Errors;
using AuthPlayground.Utilities;

using Microsoft.EntityFrameworkCore;
namespace AuthPlayground.Services.PasswordReset;

public class PasswordResetService
{
  private readonly AppDbContext _db;
  private readonly PasswordHasher _hasher;
  private readonly IEmailSender _email;
  private readonly TimeSpan _tokenTtl = TimeSpan.FromHours(1); // adjust as needed

  public PasswordResetService(AppDbContext db, PasswordHasher hasher, IEmailSender email)
  {
    _db = db;
    _hasher = hasher;
    _email = email;
  }

  // Create a token and persist its hash
  public async Task<Result<NoResult, CreatePasswordResetTokenForEmailError>> CreatePasswordResetTokenForEmailAsync(string email)
  {
    var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
    if (user == null)
      return Result<NoResult, CreatePasswordResetTokenForEmailError>.Fail(CreatePasswordResetTokenForEmailError.UserNotFound);
    
    // Per-account rate limit
    var tooManyRecent = await _db.PasswordResetTokens
    .Where(x => x.UserId == user.Id &&
                x.CreatedAt > DateTime.UtcNow.AddMinutes(-5)) // lookback window
    .CountAsync();

    if (tooManyRecent >= 3)
      return Result<NoResult, CreatePasswordResetTokenForEmailError>.Fail(CreatePasswordResetTokenForEmailError.TooManyRequests);

    string tokenString;
    byte[] tokenBytes;
    byte[] tokenHash;
    try
    {
      (tokenString, tokenBytes) = TokenUtils.CreateRandomToken();
      tokenHash = TokenUtils.Sha256(tokenBytes);
    }
    catch
    {
      throw new Exception("Failed to create password reset token");
    }

    var pr = new PasswordResetToken
    {
      UserId = user.Id,
      TokenHash = tokenHash,
      ExpiresAt = DateTime.UtcNow.Add(_tokenTtl),
      Used = false
    };

    _db.PasswordResetTokens.Add(pr);
    await _db.SaveChangesAsync();

    // Compose link. In production, use your real domain and email service.
    string resetUrl = $"https://yourapp.com/auth/reset-password?token={Uri.EscapeDataString(tokenString)}";

    // TODO: Send email with the resetUrl. For dev, log it:
    Console.WriteLine("PASSWORD RESET LINK:");
    Console.WriteLine(resetUrl);
    await _email.SendEmailAsync(
        user.Email,
        "Password Reset!",
        $"Thanks for registering! Here is your PASSWORD RESET LINK: {resetUrl}");

    return Result<NoResult, CreatePasswordResetTokenForEmailError>.Success(new NoResult());
  }

  // Validate token: returns User if valid, and marks token as used
  public async Task<Result<NoResult, ValidateAndConsumeTokenError>> ValidateAndConsumeTokenAsync(string tokenString, string newPassword)
  {
    // Validate password strength here (min length, complexity)
    if (newPassword.Length < 8)
      return Result<NoResult, ValidateAndConsumeTokenError>.Fail(ValidateAndConsumeTokenError.PasswordWeak);

    byte[] tokenHash;
    try
    {
      tokenHash = TokenUtils.Sha256FromTokenString(tokenString);
    }
    catch
    {
      throw new Exception("Failed to hash password reset token");
    }

    var tokenEntry = await _db.PasswordResetTokens
        .Include(t => t.User)
        .Where(t => !t.Used && t.ExpiresAt > DateTime.UtcNow)
        .FirstOrDefaultAsync(t => t.TokenHash.SequenceEqual(tokenHash));

    if (tokenEntry == null || tokenEntry.User == null)
      return Result<NoResult, ValidateAndConsumeTokenError>.Fail(ValidateAndConsumeTokenError.InvalidToken);

    // Mark used (single-use)
    tokenEntry.Used = true;

    // Hash new password
    var (hash, salt, iterations) = _hasher.HashPassword(newPassword);

    tokenEntry.User.PasswordHash = hash;
    tokenEntry.User.PasswordSalt = salt;
    tokenEntry.User.PasswordIterations = iterations;
    tokenEntry.User.UpdatedAt = DateTime.UtcNow;
    tokenEntry.User.SecurityStamp = Guid.NewGuid();

    await _db.SaveChangesAsync();

    return Result<NoResult, ValidateAndConsumeTokenError>.Success(new NoResult());
  }

  // Optional: prune expired tokens periodically
  public async Task PruneExpiredAsync()
  {
    var expired = _db.PasswordResetTokens
        .Where(t => !t.Used && t.ExpiresAt <= DateTime.UtcNow);

    _db.PasswordResetTokens.RemoveRange(expired);
    await _db.SaveChangesAsync();
  }
}

```

Register service:

```csharp
services.AddScoped<PasswordResetService>();
```

### Step 3b — Prune Expired Tokens

You already defined `PruneExpiredAsync`, so you need a scheduling mechanism. The production approaches are to use:

- Quartz.NET
- Hangfire
- A cron job (Linux service)
- Azure WebJob / AWS scheduled task
- Background job
    
    This requires **no external dependencies** and runs inside your ASP.NET host.
    
    Step 1 — Create a background worker
    
    ```csharp
    using Microsoft.Extensions.Hosting;
    using Microsoft.Extensions.DependencyInjection;
    using AuthPlayground.Services.PasswordReset;
    
    namespace AuthPlayground.Services.TokenPrune;
    
    public class TokenPruneBackgroundService : BackgroundService
    {
        private readonly IServiceProvider _services;
    
        public TokenPruneBackgroundService(IServiceProvider services)
        {
            _services = services;
        }
    
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Run forever until shutdown
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    using var scope = _services.CreateScope();
                    var service = scope.ServiceProvider.GetRequiredService<PasswordResetService>();
    
                    await service.PruneExpiredAsync();
                }
                catch (Exception ex)
                {
                    // log
                    Console.WriteLine("Pruning failed: " + ex);
                }
    
                // Run every hour
                await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
            }
        }
    }
    ```
    
    Step 2 — Register it in Program.cs
    
    ```csharp
    services.AddHostedService<TokenPruneBackgroundService>();
    ```
    

---

### Step 4 — Request Password Reset Endpoint

Endpoint: `POST /auth/request-password-reset`

- Input: `{ "email": "..." }`
- Response: generic success message
- Side effect: create token only if email exists; send email in background (or log link in dev)

```csharp
using FastEndpoints;
using AuthPlayground.Services.PasswordReset;

namespace WebAPI.Endpoints.auth;

public record RequestPasswordResetRequest(string email);
public class RequestPasswordResetEndpoint(PasswordResetService passwordResetService) : Endpoint<RequestPasswordResetRequest, EmptyResponse>
{
  private readonly PasswordResetService _passwordResetService = passwordResetService;

  public override void Configure()
  {
    Post("/auth/request-password-reset");
    AllowAnonymous();
  }

  public override async Task HandleAsync(RequestPasswordResetRequest req, CancellationToken ct)
  {
    var result = await _passwordResetService.CreatePasswordResetTokenForEmailAsync(req.email);

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

### Step 5 — Reset password Endpoint:

Endpoint: `POST /auth/reset-password`

- Input: `{ "token": "...", "newPassword": "..." }`
- Validate token, update password, mark token used

```csharp
using FastEndpoints;
using AuthPlayerground.Services.PasswordReset;

namespace WebAPI.Endpoints.auth;

public record ResetPasswordRequest(string tokenString, string newPassword);
public class ResetPasswordEndpoint(PasswordResetService passwordResetService) : Endpoint<ResetPasswordRequest, EmptyResponse>
{
  private readonly PasswordResetService _passwordResetService = passwordResetService;

  public override void Configure()
  {
    Post("/auth/reset-password");
    AllowAnonymous();
  }

  public override async Task HandleAsync(ResetPasswordRequest req, CancellationToken ct)
  {
    var result = await _passwordResetService.ValidateAndConsumeTokenAsync(req.tokenString, req.newPassword);

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

### Rate Limit the `request-password-reset` Endpoint.

Below is a complete, minimal FastEndpoints-compatible example showing how to configure ASP.NET built-in rate limiting (TokenBucket per IP).

```csharp
using FastEndpoints;
using Microsoft.EntityFrameworkCore;
using AuthPlayground;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuth(options =>
    options.UseSqlite(
    builder.Configuration.GetConnectionString("AppDatabase")
    ??
    throw new InvalidOperationException("Connection string 'AppDatabase' not found.")
  )
);
builder.Services.AddFastEndpoints();

// Configure built-in ASP.NET Rate Limiter
builder.Services.AddRateLimiter(options =>
{
  // Token bucket per IP
  options.AddPolicy("PasswordResetIPPolicy", httpContext =>
  {
    // Get the client IP; prefer X-Forwarded-For if behind a proxy (ensure forwarded headers are configured!)
    var ip = httpContext.Connection.RemoteIpAddress?.ToString()
               ?? httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault()
               ?? "unknown";

    return RateLimitPartition.GetTokenBucketLimiter(
          partitionKey: ip,
          factory: key => new TokenBucketRateLimiterOptions
          {
            TokenLimit = 5,                // max burst
            TokensPerPeriod = 5,           // refill tokens per period
            ReplenishmentPeriod = TimeSpan.FromMinutes(1),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0,
            AutoReplenishment = true
          });
  });

  // Optional: customize fallback response on rejection
  options.OnRejected = async (context, ct) =>
  {
    context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
    await context.HttpContext.Response.WriteAsync("Too many requests. Try again later.", ct);
  };
});

var app = builder.Build();

app.UseRateLimiter();

// Configure Endpoints
app.UseDefaultExceptionHandler()
   .UseFastEndpoints();

app.Run();

```

- `TokenBucketLimiter`:
    - `ReplenishmentPeriod` is the **interval after which `TokensPerPeriod` are added**.
    - `TokenLimit` is the maximum number of tokens in the bucket.
    - `AutoReplenishment = true` ensures tokens refill automatically.
- **Forwarded headers / proxies**: If your app sits behind a load balancer / reverse proxy, the IP from `Connection.RemoteIpAddress` may be the proxy. Configure `ForwardedHeaders` middleware and use `X-Forwarded-For` (and trust your proxy) before the rate limiter so the limiter sees the real client IP.
- **Distributed environments**: The built-in rate limiter is in-memory per host by default. If you run multiple instances you may want a distributed limiter (Redis) or a central token bucket. For distributed rate limiting, look at libraries or implement a central counter in Redis.
- **Different limiter types**: Token bucket is good for bursty traffic. For strict windows use `GetFixedWindowLimiter` or `GetSlidingWindowLimiter`.

Then apply it to your endpoint:

```csharp
using FastEndpoints;
using Core.Services.PasswordReset;

namespace WebAPI.Endpoints.auth;

public record RequestPasswordResetRequest(string email);
public class RequestPasswordResetEndpoint(PasswordResetService passwordResetService) : Endpoint<RequestPasswordResetRequest, EmptyResponse>
{
  private readonly PasswordResetService _passwordResetService = passwordResetService;

  public override void Configure()
  {
    Post("/auth/request-password-reset");
    AllowAnonymous();

    // Attach the rate-limiter policy HERE
    Options(opt => opt.RequireRateLimiting("PasswordResetIPPolicy"));
  }

  public override async Task HandleAsync(RequestPasswordResetRequest req, CancellationToken ct)
  {
    var result = await _passwordResetService.CreatePasswordResetTokenForEmailAsync(req.email);

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

- Every IP gets **5 token reset attempts per minute**.
- Excess requests are rejected with **HTTP 429** before your endpoint executes.
- The FastEndpoint uses the attribute:
    
    ```csharp
    Options(opt => opt.RequireRateLimiting("PasswordResetIPPolicy"));
    ```
    
    which binds the ASP.NET Core rate-limiter to the specific FastEndpoints route.
    
- Rate limiting occurs **before** model binding or request body reading, so it protects CPU and database.

---

### 🧪 Testing

1. `POST /auth/request-password-reset` with a registered user's email.
    - Check console output for the link (in dev).
    - You’ll see: `https://yourapp.com/auth/reset-password?token=<token>`
2. `POST /auth/reset-password` with:

```json
{
  "tokenString": "<token-from-link>",
  "newPassword": "NewStrongPassword123!"
}
```

- Should return `Password reset successfully`.
1. Try reusing the token → should fail.
2. Try an expired token (manually set `ExpiresAt` in DB earlier) → should fail.

---

### 🎉 You now have:

- Safe, single-use, time-limited password reset tokens.
- Token storage that stores only a SHA256 hash.
- Endpoints for requesting and performing password resets.
- Guidance for invalidating sessions and other hardening.
