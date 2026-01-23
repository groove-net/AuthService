using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

public class AuthDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<AuthDbContext>();

        // 1. Define your provider and connection string for design-time (migrations)
        optionsBuilder.UseSqlite("Data Source=../database.db");

        // 2. Create a "Dummy" or "Mock" dispatcher
        // Since migrations don't actually fire events, we just need a non-null instance
        IDomainEventDispatcher dummyDispatcher = new DesignTimeDispatcher();

        return new AuthDbContext(optionsBuilder.Options, dummyDispatcher);
    }
}

// A simple internal class just to satisfy the constructor during migration creation
internal class DesignTimeDispatcher : IDomainEventDispatcher
{
    public Task DispatchDomainEventsAsync(IEnumerable<Entity> entities, CancellationToken ct)
        => Task.CompletedTask;
}
