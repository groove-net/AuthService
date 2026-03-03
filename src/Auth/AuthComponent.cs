using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Auth.Domain;
using Auth.Application;
using Auth.Infrastructure;

namespace Auth;

public static class AuthComponent
{
    private static readonly IServiceProvider _provider;

    static AuthComponent()
    {
        var services = new ServiceCollection();

        // 1. Databases
        // The library must define its own connection String here
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
        services.AddSingleton<IConfirmationTokenGenerator, ConfirmationTokenGenerator>();
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

        // 3. Domain Event Handlers
        services.AddScoped<IDomainEventHandler<UserRegisteredDomainEvent>, UserRegisteredDomainEventHandler>();
        services.AddScoped<IDomainEventHandler<PasswordResetTokenGrantedDomainEvent>, PasswordResetTokenGrantedDomainEventHandler>();

        // 3. Background services
        services.AddHostedService<PruneExpiredTokens>();

        // 4. Register all Use Cases
        services.AddScoped<Confirm2fa>();
        services.AddScoped<ConfirmEmail>();
        services.AddScoped<Disable2fa>();
        services.AddScoped<RequestPasswordReset>();
        services.AddScoped<Register>();
        services.AddScoped<ResendEmailConfirmation>();
        services.AddScoped<Setup2fa>();
        services.AddScoped<UseRecoveryCode>();
        services.AddScoped<Login>();
        services.AddScoped<ResetPassword>();
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

    public static Task<Result<RegisterResult, Error>> Register(String username, String email, String password)
        => Execute<Register, Result<RegisterResult, Error>>(uc => uc.Handle(username, email, password));

    public static Task<Result<EmptyResult, Error>> ConfirmEmail(String token)
        => Execute<ConfirmEmail, Result<EmptyResult, Error>>(uc => uc.Handle(token));

    public static Task<Result<EmptyResult, Error>> ResendEmailConfirmation(String userEmail)
        => Execute<ResendEmailConfirmation, Result<EmptyResult, Error>>(uc => uc.Handle(userEmail));

    // --- AUTHENTICATION ---

    public static Task<Result<LoginResult, Error>> Login(String username, String password)
        => Execute<Login, Result<LoginResult, Error>>(uc => uc.Handle(username, password));

    public static Task<Result<Verify2faResult, Error>> VerifyTwoFactor(String challengeToken, String code)
        => Execute<Verify2fa, Result<Verify2faResult, Error>>(uc => uc.Handle(challengeToken, code));

    public static Task<Result<UseRecoveryCodeResult, Error>> UseRecoveryCode(String challengeToken, String recoveryCode)
        => Execute<UseRecoveryCode, Result<UseRecoveryCodeResult, Error>>(uc => uc.Handle(challengeToken, recoveryCode));

    // --- PASSWORD RECOVERY ---

    public static Task<Result<EmptyResult, Error>> RequestPasswordReset(String email)
        => Execute<RequestPasswordReset, Result<EmptyResult, Error>>(uc => uc.Handle(email));

    public static Task<Result<EmptyResult, Error>> ResetPassword(String token, String newPassword)
        => Execute<ResetPassword, Result<EmptyResult, Error>>(uc => uc.Handle(token, newPassword));

    // --- MFA MANAGEMENT ---

    public static Task<Result<Setup2faResult, Error>> GetTwoFactorSetup(String issuer, Guid userId)
        => Execute<Setup2fa, Result<Setup2faResult, Error>>(uc => uc.Handle(issuer, userId));

    public static Task<Result<Confirm2faResult, Error>> ConfirmTwoFactorSetup(Guid userId, String code)
        => Execute<Confirm2fa, Result<Confirm2faResult, Error>>(uc => uc.Handle(userId, code));

    public static Task<Result<EmptyResult, Error>> DisableTwoFactor(Guid userId)
        => Execute<Disable2fa, Result<EmptyResult, Error>>(uc => uc.Handle(userId));
}

public record class Confirm2faResult(
    IReadOnlyList<string> RecoveryCodes
);

public record class LoginResult(
    Guid UserId,
    string Username,
    bool RequiresTwoFactore,
    string? ChallengeToken
);

public record class RegisterResult(
    Guid UserId
);

public record class Setup2faResult(
    string QrCodeDataUrl
);

public record class UseRecoveryCodeResult
(
    Guid id,
    string username,
    string email
);

public record class Verify2faResult
(
    Guid id,
    string username,
    string email
);
