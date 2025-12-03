using Core.Models;

using Microsoft.EntityFrameworkCore;

namespace Core.Data;

public class AppDbContext : DbContext
{
  public DbSet<User> Users => Set<User>();
  public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();

  public AppDbContext(DbContextOptions<AppDbContext> options)
      : base(options)
  {
  }
}