using Auth.Domain;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure;

internal class UserRepository : IUserRepository, IDisposable
{
    private readonly AuthDbContext _context;

    public UserRepository(AuthDbContext context)
    {
        _context = context;
    }

    public IUnitOfWork UnitOfWork => _context;

    public async Task<bool> ExistsByUsernameAsync(string username)
    {
        return await _context.Users
            .AnyAsync(u => u.Username == username);
    }

    public async Task<bool> ExistsByEmailAsync(string email)
    {
        return await _context.Users
            .AnyAsync(u => u.Email == email);
    }

    public async Task<User?> FindByIdAsync(Guid id)
    {
        // We include the tokens collection because several UseCases 
        // need to manipulate the user's tokens (like invalidating them).
        return await _context.Users
            .Include(u => u.PasswordResetTokens)
            .FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<User?> FindByUsernameAsync(string username)
    {
        return await _context.Users
            .Include(u => u.PasswordResetTokens)
            .FirstOrDefaultAsync(u => u.Username == username);
    }

    public async Task<User?> FindByEmailAsync(string email)
    {
        return await _context.Users
            .Include(u => u.PasswordResetTokens)
            .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<PasswordResetToken?> GetPasswordResetTokenInfo(byte[] tokenHash)
    {
        // Critical: We include the User so the ValidatePasswordResetToken UseCase 
        // has access to the aggregate root to call ChangePassword().
        return await _context.Set<PasswordResetToken>()
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
    }

    public async Task AddAsync(User user)
    {
        await _context.Users.AddAsync(user);
    }

    public async Task PruneExpiredPasswordResetTokens()
    {
        // Bulk delete for efficiency if your EF version supports it (EF7+)
        await _context.Set<PasswordResetToken>()
            .Where(t => t.ExpiresAt < DateTime.UtcNow || t.Used)
            .ExecuteDeleteAsync();
    }

    public async Task<int> PasswordResetTokenCountWithinLastXMinutes(Guid id, int minutes)
    {
        var threshold = DateTime.UtcNow.AddMinutes(-minutes);

        // We query the tokens directly for performance rather than loading the User aggregate
        return await _context.Set<PasswordResetToken>()
            .CountAsync(t => t.User!.Id == id && t.CreatedAt >= threshold);
    }

    private bool disposed = false;

    protected virtual void Dispose(bool disposing)
    {
        if (!this.disposed)
        {
            if (disposing)
            {
                _context.Dispose();
            }
        }
        this.disposed = true;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}
