using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Core.Data;

public class AppDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
  public AppDbContext CreateDbContext(string[] args)
  {
    var optionsBuilder = new DbContextOptionsBuilder<AppDbContext>();

    // Use the same provider / connection string your app uses
    optionsBuilder.UseSqlite("Data Source=../Core/auth_database.db");

    return new AppDbContext(optionsBuilder.Options);
  }
}