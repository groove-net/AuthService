public interface IUserRepository : IRepository<User>
{
    Task<Boolean> ExistsByUsernameAsync(String username);
    Task<Boolean> ExistsByEmailAsync(String email);
    Task<User?> FindByIdAsync(Guid id);
    Task<User?> FindByUsernameAsync(String username);
    Task<User?> FindByEmailAsync(String email);
    Task<PasswordResetToken?> GetPasswordResetTokenInfo(Byte[] tokenHash);
    Task AddAsync(User user);
    Task PruneExpiredPasswordResetTokens();
    Task<Int32> PasswordResetTokenCountWithinLastXMinutes(Guid id, Int32 minutes);
}
