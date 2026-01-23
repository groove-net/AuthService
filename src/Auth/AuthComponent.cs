using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;

namespace Auth;

public static class AuthComponent
{
    private static readonly IServiceProvider _provider;

    static AuthComponent()
    {
        var services = new ServiceCollection();

        // 1. Databases
        // The library must define its own connection string here
        services.AddDbContext<AuthDbContext>(options =>
            options.UseSqlite("Data Source=../database.db"));
        // Register the DbContext as the IUnitOfWork
        services.AddScoped<IUnitOfWork>(sp => sp.GetRequiredService<AuthDbContext>());
        // Register the dispatcher
        services.AddScoped<IDomainEventDispatcher, DomainEventDispatcher>();
        // Register the repositories
        services.AddScoped<IUserRepository, UserRepository>();

        // 2. Application Interfaces & Infrastructure
        services.AddLogging(builder => // Configure logging
            {
                builder.AddConsole(); // Tells the library to write to the terminal
                builder.SetMinimumLevel(LogLevel.Information); // Control the "noise" level
            });
        services.AddSingleton<IEmailSender, SmtpEmailSender>();
        services.AddSingleton<ISecretProtector, AesGcmSecretProtector>();
        services.AddSingleton<ITwoFactorChallenge, TwoFactorChallenge>();
        var keyPath = File.Exists("/run/secrets/key") ? "/run/secrets/key" : "secrets/key";
        if (!File.Exists(keyPath))
            throw new InvalidOperationException($"Cryptographic Key missing at {keyPath}. The Auth Component cannot start.");
        var base64Key = File.ReadAllText(keyPath).Trim();
        var keyBytes = Convert.FromBase64String(base64Key);
        services.AddSingleton<ISecretProtector>(new AesGcmSecretProtector(keyBytes));
        services.AddDataProtection();
        services.AddScoped<IDataProtector>(sp =>
        {
            var provider = sp.GetRequiredService<IDataProtectionProvider>();
            return provider.CreateProtector("AuthService.Default.Purpose");
        });

        // 3. Background services
        services.AddHostedService<PruneExpiredTokens>();

        // 4. Register all Use Cases
        services.AddScoped<Confirm2fa>();
        services.AddScoped<ConfirmEmail>();
        services.AddScoped<Disable2fa>();
        services.AddScoped<EmailPasswordResetToken>();
        services.AddScoped<RegisterUser>();
        services.AddScoped<SendEmailConfirmation>();
        services.AddScoped<Setup2fa>();
        services.AddScoped<UseRecoveryCode>();
        services.AddScoped<UserLogin>();
        services.AddScoped<ValidatePasswordResetToken>();
        services.AddScoped<Verify2fa>();

        _provider = services.BuildServiceProvider();
    }

    /// <summary>
    /// Helper to execute a use case within a fresh DI scope.
    /// This ensures the IUnitOfWork and Repositories are disposed correctly.
    /// </summary>
    private static async Task<TResult> Execute<TUseCase, TResult>(Func<TUseCase, Task<TResult>> action)
        where TUseCase : notnull
    {
        using var scope = _provider.CreateScope();
        var useCase = scope.ServiceProvider.GetRequiredService<TUseCase>();
        return await action(useCase);
    }

    // --- REGISTRATION & CONFIRMATION ---

    public static Task<Result<RegisterUser.Value, Error>> RegisterUser(string username, string email, string password)
        => Execute<RegisterUser, Result<RegisterUser.Value, Error>>(uc => uc.Handle(username, email, password));

    public static Task<Result<ConfirmEmail.Value, Error>> ConfirmEmail(string token)
        => Execute<ConfirmEmail, Result<ConfirmEmail.Value, Error>>(uc => uc.Handle(token));

    public static Task<Result<SendEmailConfirmation.Value, Error>> ResendEmailConfirmation(Guid userId)
        => Execute<SendEmailConfirmation, Result<SendEmailConfirmation.Value, Error>>(uc => uc.Handle(userId));

    // --- AUTHENTICATION ---

    public static Task<Result<UserLogin.Value, Error>> Login(string username, string password)
        => Execute<UserLogin, Result<UserLogin.Value, Error>>(uc => uc.Handle(username, password));

    public static Task<Result<Verify2fa.Value, Error>> VerifyTwoFactor(string challengeToken, string code)
        => Execute<Verify2fa, Result<Verify2fa.Value, Error>>(uc => uc.Handle(challengeToken, code));

    public static Task<Result<UseRecoveryCode.Value, Error>> UseRecoveryCode(string challengeToken, string recoveryCode)
        => Execute<UseRecoveryCode, Result<UseRecoveryCode.Value, Error>>(uc => uc.Handle(challengeToken, recoveryCode));

    // --- PASSWORD RECOVERY ---

    public static Task<Result<EmailPasswordResetToken.Value, Error>> RequestPasswordReset(string email)
        => Execute<EmailPasswordResetToken, Result<EmailPasswordResetToken.Value, Error>>(uc => uc.Handle(email));

    public static Task<Result<ValidatePasswordResetToken.Value, Error>> ResetPassword(string token, string newPassword)
        => Execute<ValidatePasswordResetToken, Result<ValidatePasswordResetToken.Value, Error>>(uc => uc.Handle(token, newPassword));

    // --- MFA MANAGEMENT ---

    public static Task<Result<Setup2fa.Value, Error>> GetTwoFactorSetup(string issuer, Guid userId)
        => Execute<Setup2fa, Result<Setup2fa.Value, Error>>(uc => uc.Handle(issuer, userId));

    public static Task<Result<Confirm2fa.Value, Error>> ConfirmTwoFactorSetup(Guid userId, string code)
        => Execute<Confirm2fa, Result<Confirm2fa.Value, Error>>(uc => uc.Handle(userId, code));

    public static Task<Result<Disable2fa.Value, Error>> DisableTwoFactor(Guid userId)
        => Execute<Disable2fa, Result<Disable2fa.Value, Error>>(uc => uc.Handle(userId));
}
