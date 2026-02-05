If you only have one back end service interfacing with your ui, you may implement this logic there. However, if you have multiple services interacting with your ui, create a gateway and implement this there. Afterwards, discard all authentication checks. Simply perform service to service communication. Only the gateway talks to the backend services, and all backend services trust the gateway fully. Of course, the gateway fully authenticates and authorizes the request and backend services are never exposed to the public internet. The gateway can then forwards the **resolved identity** to backend services.

Backend services MUST still enforce:

- **authorization rules based on user claims**
- **input validation and tenant boundaries**
- **service-to-service authentication** (between internal services only)

But they do NOT authenticate the user again.

### Step 1 — When creating a cookie, store the stamp as a claim

When signing in:

```csharp
var claims = new List<Claim>
{
    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
    new Claim("security_stamp", user.SecurityStamp.ToString())
};
```

Include it in your cookie identity.

### Step 2 — Add validation inside cookie authentication middleware

In **Program.cs** of the host app:

```csharp
builder.Services.AddAuthentication("Cookies")
    .AddCookie("Cookies", options =>
    {
        // =====================================
        // Cookie lifetime configuration
        // =====================================

        // Recommended for most logins:
        options.ExpireTimeSpan = TimeSpan.FromHours(12); // Absolute cookie lifetime (12 hours)

        // If true: each successful request resets the expiration timer
        options.SlidingExpiration = true;

        // Whether to persist the cookie even after browser is closed
        options.Cookie.IsEssential = true;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;

        // You can optionally set a fixed expiration date:
        // options.Cookie.Expires = DateTimeOffset.UtcNow.AddHours(12);

        // =====================================
        // Validation logic: Security Stamp check (Optional)
        // =====================================

        options.Events = new CookieAuthenticationEvents
        {
            OnValidatePrincipal = async context =>
            {
                var userId = context.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var cookieStamp = context.Principal.FindFirst("security_stamp")?.Value;

                if (userId == null || cookieStamp == null)
                {
                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync("Cookies");
                    return;
                }

                var db = context.HttpContext.RequestServices.GetRequiredService<AppDbContext>();
                var user = await db.Users.FindAsync(Guid.Parse(userId));

                if (user == null || user.SecurityStamp.ToString() != cookieStamp)
                {
                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync("Cookies");
                }
            }
        };
    });
```

When you set `options.ExpireTimeSpan`, ASP.NET generates a cookie with a **fixed expiration timestamp**. After that timestamp, the cookie is dead regardless of anything else (even if the security_stamp matches).

If `options.SlidingExpiration` is enabled, each time the cookie is successfully validated:

- The expiration timestamp is refreshed.
- The browser receives a **new Set-Cookie** header with an extended expiry.

This keeps active sessions alive while killing inactive ones.

Finally, if the security stamp check is included and the stamp changes:

1. All existing cookies fail `OnValidatePrincipal`.
2. ASP.NET rejects the principal.
3. The cookie is immediately invalidated.

This gives you instant **time-based expiration** + **session revocation**.

Additionally, here is a version without time-based expiration and persistence. You can use this with the security stamp :

```csharp
// Recommended for most logins:
options.ExpireTimeSpan = TimeSpan.FromHours(12); // Absolute cookie lifetime (12 hours)

// If true: each successful request resets the expiration timer
options.SlidingExpiration = true;

// Whether to persist the cookie even after browser is closed
options.Cookie.IsEssential = true;
options.Cookie.HttpOnly = true;
options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
options.Cookie.SameSite = SameSiteMode.Strict;

options.Cookie.MaxAge = null; // no explicit expiry → becomes session cookie
options.SlidingExpiration = false;
```
