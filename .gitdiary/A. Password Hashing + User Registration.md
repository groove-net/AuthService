### Step 0 — Create a class library and install packages

```bash
$ dotnet new classlib -n AuthPlayground -o src/AuthPlayground
```

```bash
# Provides interfaces Dependency Injection
dotnet add src/Auth package Microsoft.Extensions.DependencyInjection.Abstractions
# Provides logging
dotnet add src/Auth package Microsoft.Extensions.Logging --version 8.0
# Provides interface Entity Framework
dotnet add src/Auth package Microsoft.EntityFrameworkCore --version 8.0
dotnet add src/Auth package Microsoft.EntityFrameworkCore.Design --version 8.0
# Database provider of your choice (e.g. SQLite)
dotnet add src/Auth package Microsoft.EntityFrameworkCore.Sqlite --version 8.0
```

### **Step 1 — Create the User Model (minimal but production-ready)**

You will store:

- Username
- Email
- Whether email is confirmed
- Password hash
- Salt
- PBKDF2 iteration count (good practice — iteration count may change over time)
- Timestamps

Here’s the recommended model:

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

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }
}
```

We also want `Result` and `Error` models to utilize the Result Pattern.

```csharp
namespace AuthPlayground.Models;

public record Result<TValue, TError>
{
  public TValue? Value { get; init; }
  public TError? Error { get; init; }
  public bool IsSuccess => Error is null;

  public static Result<TValue, TError> Success(TValue value) => new() { Value = value };
  public static Result<TValue, TError> Fail(TError error) => new() { Error = error };
}

public record NoResult();
```

```csharp
namespace AuthPlayground.Models;

public abstract record Error(string Code, string Message)
{
  public override string ToString() => Code;
}
```

This is all you need to start.

### **Step 2 — Create a PBKDF2 Password Hasher Utility**

We use Microsoft’s built–in PBKDF2 implementation:

- Random 16 or 32 byte salt
- 100,000–300,000 iterations (you choose)
- 256-bit hash output

Example production-grade PBKDF2 hasher:

```csharp
using System.Security.Cryptography;

namespace AuthPlayground.Utilities;

public class PasswordHasher
{
    private const int SaltSize = 16; // 128-bit
    private const int KeySize = 32;  // 256-bit

    // Choose an iteration count suitable for modern hardware
    private const int Iterations = 150_000;

    public (byte[] hash, byte[] salt, int iterations) HashPassword(string password)
    {
        // Create salt
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

        // Derive key
        using var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256
        );

        byte[] key = pbkdf2.GetBytes(KeySize);

        return (key, salt, Iterations);
    }

    public bool VerifyPassword(string password, byte[] salt, int iterations, byte[] expectedHash)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256
        );

        byte[] computed = pbkdf2.GetBytes(expectedHash.Length);

        return CryptographicOperations.FixedTimeEquals(computed, expectedHash);
    }
}
```

Why is this production-ready?

✔ Uses a slow, computationally expensive hashing algorithm

✔ Uses a random salt

✔ Uses fixed-time comparison to avoid timing attacks

✔ Stores iteration count (so you can increase it later without invalidating accounts)

### Step 3 — Configure Relational Database Model with EF Core and `AppDbContext`

```csharp
using AuthPlayground.Models;

using Microsoft.EntityFrameworkCore;

namespace AuthPlayground.Data;

public class AppDbContext : DbContext
{
  public DbSet<User> Users => Set<User>();

  public AppDbContext(DbContextOptions<AppDbContext> options)
      : base(options)
  {
  }
}
```

See the ***“Using the EF Core Model”*** section in [Using Entity Framework Core for Relational Databases](https://www.notion.so/Using-Entity-Framework-Core-for-Relational-Databases-5ddd360f4b00493099a870defe1b4858?pvs=21) for  info on creating and configuring the Model.

Then create the `AppDbContextFactory`.

```csharp
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace AuthPlayground.Data;

public class AppDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
  public AppDbContext CreateDbContext(string[] args)
  {
    var optionsBuilder = new DbContextOptionsBuilder<AppDbContext>();

    // Use the same provider / connection string your app uses
    optionsBuilder.UseSqlite("Data Source=../AuthPlayground/auth_database.db");

    return new AppDbContext(optionsBuilder.Options);
  }
}
```

### **Step 5 — Create Authentication Errors**

```csharp
using AuthPlayground.Models;

namespace AuthPlayground.Services.Authentication.Errors;

public record RegisterUserError : Error
{
  private RegisterUserError(string code, string message)
      : base(code, message) { }

  public static readonly RegisterUserError UsernameExists =
      new("UsernameExists", "The username is already taken.");

  public static readonly RegisterUserError EmailExists =
      new("EmailExists", "The email address is already registered.");

  public static readonly RegisterUserError WeakPassword =
      new("WeakPassword", "The provided password does not meet security requirements.");

  public static readonly RegisterUserError ValidationFailed =
      new("ValidationFailed", "One or more fields are invalid.");
}
```

### **Step 6 — Implement a Authentication Service**

This is a minimal but production-quality authentication service:

```csharp
using AuthPlayground.Data;
using AuthPlayground.Models;
using AuthPlayground.Services.Authentication.Errors;
using AuthPlayground.Utilities;

using Microsoft.EntityFrameworkCore;

namespace AuthPlayground.Services.Authentication;

public class AuthenticationService
{
  private readonly AppDbContext _db;
  private readonly PasswordHasher _hasher;

  public AuthenticationService(AppDbContext db, PasswordHasher hasher)
  {
    _db = db;
    _hasher = hasher;
  }

  public async Task<Result<User, RegisterUserError>> Register(string Username, string Email, string Password)
  {
    User user;

    // Check if username or email exists
    if (await _db.Users.AnyAsync(u => u.Username == Username))
      return Result<User, RegisterUserError>.Fail(RegisterUserError.UsernameExists);

    if (await _db.Users.AnyAsync(u => u.Email == Email))
      return Result<User, RegisterUserError>.Fail(RegisterUserError.EmailExists);

    // Hash password
    var (hash, salt, iterations) = _hasher.HashPassword(Password);

    user = new User
    {
      Username = Username,
      Email = Email,
      PasswordHash = hash,
      PasswordSalt = salt,
      PasswordIterations = iterations,
      EmailConfirmed = false
    };

    _db.Users.Add(user);
    await _db.SaveChangesAsync();

    // TODO: send email confirmation token

    return Result<User, RegisterUserError>.Success(user);
  }
}
```

### **Step 5 — Configure Services**

Configure the services in `AuthPlaygroundServiceCollectionExtensions.cs`:

```csharp
using AuthPlayground.Data;
using AuthPlayground.Services.Authentication;
using AuthPlayground.Utilities;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthPlayground;

public static class CoreServiceCollectionExtensions
{
  public static IServiceCollection AddAuth(this IServiceCollection services, Action<DbContextOptionsBuilder> configureDb)
  {
    ArgumentNullException.ThrowIfNull(configureDb);
    // register services here
    services.AddScoped<PasswordHasher>();
    services.AddScoped<AuthenticationService>();
    services.AddDbContext<AppDbContext>(configureDb);
    return services;
  }
}
```

### **Step 6 — Implement the Host Web API App (FastEndpoints)**

- Create project:
    
    ```bash
    dotnet new web -n WebAPI -o src/WebAPI
    ```
    
- Add reference:
    
    ```bash
    dotnet add reference ../AuthPlayground/AuthPlayground.csproj
    ```
    
- Install Entity Framework Packages:
    
    ```bash
    dotnet tool uninstall --global dotnet-ef --version 8.0
    dotnet tool install --global dotnet-ef --version 8.0
    dotnet add package Microsoft.EntityFrameworkCore.Design --version 8.0
    dotnet add package Microsoft.EntityFrameworkCore.Relational --version 8.0
    dotnet add package Microsoft.EntityFrameworkCore.Tools --version 8.0
    ```
    
- Install database provider (we will use Sqlite):
    
    ```bash
    dotnet add package [Microsoft.EntityFrameworkCore.Sqlite](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore.Sqlite) --version 8.0
    ```
    
- Setup your database
    
    See [this page](https://www.notion.so/Databases-20e96e57749880b9bbdcd585cb1faeeb?pvs=21) on how to setup your relational database.
    
- Create a connection string in the `appsettings.Development.json` file:
    
    In the `appsettings.Development.json` and `appsettings.json` file, we can define connection strings that our app will use to connect to our database. We should get these strings after setting up your database.
    
    **SQLite:** 
    
    This is just the location of the SQLite file. Make sure it matches the connection string defined in the class library. The path is described with the host app root/project directory as the origin.
    
    ```json
    "ConnectionStrings": {
        "AppDatabase": "Data Source=../AuthPlayground/auth_database.db"
    }
    ```
    
    See [Communication with datastores](https://www.notion.so/Communication-with-datastores-23e96e57749880fe8c24d7e5d2cad4e3?pvs=21) for more.
    
- Program.cs
    
    ```csharp
    using FastEndpoints;
    using Microsoft.EntityFrameworkCore;
    using AuthPlayground;
    
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
    app.UseDefaultExceptionHandler()
       .UseFastEndpoints();
    
    app.Run();
    
    ```
    
- Disable the ASP.NET Core Diagnostic logging for unhandled exceptions in order to avoid duplicate log entries.
    
    ```json
    // appsettings.json
    {
      "Logging": {
        "LogLevel": {
          "Default": "Warning",
          //add this
          "Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware": "None"
        }
      }
    ```
    
- Perform initial migrations and updates
    
    ```bash
    dotnet ef migrations add InitialCreate --project ../AuthPlayground --startup-project .
    dotnet ef database update --project ../AuthPlayground --startup-project .
    ```
    
    See the ***“Using migration”*** section in [Using Entity Framework Core for Relational Databases](https://www.notion.so/Using-Entity-Framework-Core-for-Relational-Databases-5ddd360f4b00493099a870defe1b4858?pvs=21) for more info. 
    
- Implement a minimal`POST /auth/register` endpoint:
    
    ```csharp
    // ./Endpoints/auth/register.cs
    
    using FastEndpoints;
    using AuthPlayground.Services.Authentication;
    
    namespace WebAPI.Endpoints.auth;
    
    public record RegisterRequest(string Username, string Email, string Password);
    public record RegisterResponse(Guid Id);
    public class RegisterEndpoint(AuthenticationService authenticationService) : Endpoint<RegisterRequest, RegisterResponse>
    {
      private readonly AuthenticationService _authenticationService = authenticationService;
    
      public override void Configure()
      {
        Post("/auth/register");
        AllowAnonymous();
      }
    
      public override async Task HandleAsync(RegisterRequest req, CancellationToken ct)
      {
        var result = await _authenticationService.Register(req.Username, req.Email, req.Password);
    
        if (!result.IsSuccess || result.Value == null)
        {
          string errorMessage = result.Error == null ? "An Unknown Error Has Occured." : result.Error.Message;
          AddError(errorMessage);
          await Send.ErrorsAsync();
          return;
        }
    
        await Send.OkAsync(new RegisterResponse(result.Value.Id));
      }
    }
    
    ```
    
    See [Creating a ASP.NET Core REST API App with FastEndpoints](https://www.notion.so/Creating-a-ASP-NET-Core-REST-API-App-using-FastEndpoints-11a96e57749880ecb7e0f349d796436a?pvs=21) for more.
    

### 🎉 You now have:

✔ A real PBKDF2 password hashing system

✔ A real User table in SQLite

✔ A minimal, clean, production-style registration endpoint

✔ Clear separation of concerns (model, hasher, controller)

✔ A foundation for login, lockout, TFA, email confirmation, etc.
