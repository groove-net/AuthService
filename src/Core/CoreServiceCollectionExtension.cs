using Core.Data;
using Core.Services.Authentication;
using Core.Services.PasswordReset;
using Core.Services.TokenPrune;
using Core.Services.TwoFactor;
using Core.Utilities;
using Core.Utilities.EmailSender;

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
    services.AddSingleton<SmtpOptions>();
    services.AddScoped<PasswordResetService>();
    services.AddHostedService<TokenPruneBackgroundService>();
    services.AddSingleton<IEmailSender, SmtpEmailSender>();
    services.AddScoped<AuthenticationService>();

    var base64Key = File.ReadAllText(File.Exists("/run/secrets/key")
      ? "/run/secrets/key"
      : "secrets/key").Trim();
    var keyBytes = Convert.FromBase64String(base64Key);
    services.AddSingleton<ISecretProtector>(new AesGcmSecretProtector(keyBytes));
    services.AddScoped<TwoFactorUtils>();
    services.AddScoped<TwoFactorChallenge>();
    services.AddScoped<TwoFactorService>();

    services.AddDataProtection();
    services.AddDbContext<AppDbContext>(configureDb);
    return services;
  }
}