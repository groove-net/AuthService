using Core.Data;
using Core.Services.Authentication;
using Core.Utilities;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;


namespace Core;

public static class CoreServiceCollectionExtensions
{
  public static IServiceCollection AddAuth(this IServiceCollection services, Action<DbContextOptionsBuilder> configureDb)
  {
    ArgumentNullException.ThrowIfNull(configureDb);
    services.AddScoped<PasswordHasher>();
    services.AddScoped<EmailTokenGenerator>();
    services.AddScoped<AuthenticationService>();
    services.AddDataProtection();
    services.AddDbContext<AppDbContext>(configureDb);
    return services;
  }
}