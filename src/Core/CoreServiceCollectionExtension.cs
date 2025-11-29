using Core.Data;
using Core.Services.Register;
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
    services.AddScoped<RegisterService>();
    services.AddDbContext<AppDbContext>(configureDb);
    return services;
  }
}