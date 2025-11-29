using FastEndpoints;
using Microsoft.EntityFrameworkCore;
using Core;

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

var app = builder.Build();

// Configure Endpoints
app.UseDefaultExceptionHandler().UseFastEndpoints();

app.Run();