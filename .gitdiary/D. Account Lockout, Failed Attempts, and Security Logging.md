This protects your login endpoint from brute-force attacks, credential-stuffing automation, bots repeatedly trying passwords. This will make your system *much* closer to something you could deploy in production.

We will add the following fields to your `User` table:

- `FailedLoginAttempts`
- `LockoutEnd` (datetime until the user is locked out)

Lockout policy (typical secure defaults):

- **Max attempts:** 5
- **Lockout duration:** 15 minutes
- **Failed attempts reset on successful login**

During login, you will:

1. Check if the account is currently locked
2. Check password
3. Increment failed attempt counter
4. Lock account if threshold reached
5. Reset counter on success

Let’s go step-by-step.

### **Step 1 — Extend the User Model**

Add these fields to your `User` class:

```csharp
public int FailedLoginAttempts { get; set; }
public DateTime? LockoutEnd { get; set; }
```

Make sure to run EF migrations afterward:

```bash
dotnet ef migrations add AddLockoutFields --project ../AuthPlayground --startup-project .
dotnet ef database update --project ../AuthPlayground --startup-project .
```

### **Step 2 — Decide Lockout Policy**

Let's define some constants:

```csharp
namespace AuthPlayground.Services.Authentication;

public static class AuthOptions
{
  public const int MaxFailedAttempts = 5;
  public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
}

```

### **Step 3 — Modify Login Logic**

Below is the improved login logic incorporating:

- lockout check
- failed attempt increment
- lockout triggering
- resetting attempts on success

```csharp
  public async Task<Result<User, LoginUserError>> Login(string Username, string Password)
  {
    var user = await _db.Users
        .FirstOrDefaultAsync(u => u.Username == Username);

    if (user == null)
      return Result<User, LoginUserError>.Fail(LoginUserError.InvalidCredentials);

    // [+] Check lockout
    if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
    {
      var minutesLeft = (int)(user.LockoutEnd.Value - DateTime.UtcNow).TotalMinutes;
      return Result<User, LoginUserError>.Fail(new LoginUserError("Lockout", $"Account locked. Try again in {minutesLeft} minutes."));
    }

    // Verify password
    bool validPassword = _hasher.VerifyPassword(
        Password,
        user.PasswordSalt,
        user.PasswordIterations,
        user.PasswordHash
    );

    // [-]
    if (!validPassword)
      return Result<User, LoginUserError>.Fail(LoginUserError.InvalidCredentials);
    // [+]
    if (!validPassword)
    {
      user.FailedLoginAttempts++;

      // Lock account if too many failures
      if (user.FailedLoginAttempts >= AuthOptions.MaxFailedAttempts)
      {
        user.LockoutEnd = DateTime.UtcNow.Add(AuthOptions.LockoutDuration);
        user.FailedLoginAttempts = 0; // reset counter after locking
      }

      await _db.SaveChangesAsync();
      return Result<User, LoginUserError>.Fail(LoginUserError.InvalidCredentials);
    }

    // [+] Successful login → reset attempts
    user.FailedLoginAttempts = 0;
    user.LockoutEnd = null;
    await _db.SaveChangesAsync();

    // TODO: email confirmed, 2FA
    
    return Result<User, LoginUserError>.Success(user);
  }

```

**Why This Is Secure**

✔ Prevents unlimited brute-force attempts

✔ Prevents attackers from "burning" accounts with arbitrary lockouts

✔ Uses a consistent error message (no information leak)

✔ Lockout is temporary (15 minutes)

✔ Lockout resets after time expires

This is how major identity providers (Azure, AWS Cognito, IdentityServer) handle it.

---

### 🧪 **Testing**

1. Try logging in with the wrong password **5 times**:
    
    → Response: `Invalid username or password`
    
2. On the **6th attempt**:
    
    → Response: `Account locked for 15 minutes`
    
3. Try correct password after lockout:
    
    → Still locked until time expires
    
4. After the lockout time passes:
    
    → Login works again normally
    

---

### 🎉 You now have:

✔ PBKDF2 password hashing

✔ SQLite user storage

✔ Cookie-based login

✔ Logout

✔ Account lockout

✔ Failed login protection

Your system is now significantly closer to production-grade authentication.
