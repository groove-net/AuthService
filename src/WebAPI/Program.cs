using FastEndpoints;
using Microsoft.EntityFrameworkCore;
using Core;
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
app.UseDefaultExceptionHandler().UseFastEndpoints();

app.Run();