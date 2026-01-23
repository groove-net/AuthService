using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

public class AuthDbContext : DbContext, IUnitOfWork
{
    public DbSet<User> Users { get; set; } = default!;
    public DbSet<PasswordResetToken> PasswordResetTokens { get; set; } = default!;

    private readonly IDomainEventDispatcher _dispatcher;
    private IDbContextTransaction? _currentTransaction;

    public IDbContextTransaction? GetCurrentTransaction() => _currentTransaction;

    public bool HasActiveTransaction => _currentTransaction != null;

    public AuthDbContext(DbContextOptions<AuthDbContext> options, IDomainEventDispatcher dispatcher) : base(options)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        System.Diagnostics.Debug.WriteLine("AuthDbContext::ctor ->" + this.GetHashCode());
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>();
        modelBuilder.Entity<PasswordResetToken>();
    }

    public async Task<bool> SaveEntitiesAsync(CancellationToken cancellationToken = default)
    {
        // NOTE: Here we dispatch Domain Events collection. 
        // We have 2 Choices:
        // A) (preferred) Right BEFORE committing data (EF SaveChanges) into the DB will make a single transaction including  
        // side effects from the domain event handlers which are using the same DbContext with "InstancePerLifetimeScope" or "scoped" lifetime
        // B) Right AFTER committing data (EF SaveChanges) into the DB will make multiple transactions. 
        // You will need to handle eventual consistency and compensatory actions in case of failures in any of the Handlers. 

        // Find all tracked entities that have domain events
        var domainEntities = ChangeTracker
            .Entries<Entity>() // Assuming your base class is 'Entity'
            .Where(x => x.Entity.DomainEvents != null && x.Entity.DomainEvents.Any())
            .Select(x => x.Entity)
            .ToList();

        await _dispatcher.DispatchDomainEventsAsync(domainEntities, cancellationToken);

        // After executing this line all the changes (from the Command Handler and Domain Event Handlers) 
        // performed through the DbContext will be committed
        _ = await base.SaveChangesAsync(cancellationToken);

        return true;
    }

    public async Task<IDbContextTransaction?> BeginTransactionAsync()
    {
        if (_currentTransaction != null) return null;

        _currentTransaction = await Database.BeginTransactionAsync(IsolationLevel.ReadCommitted);

        return _currentTransaction;
    }

    public async Task CommitTransactionAsync(IDbContextTransaction transaction)
    {
        if (transaction == null) throw new ArgumentNullException(nameof(transaction));
        if (transaction != _currentTransaction) throw new InvalidOperationException($"Transaction {transaction.TransactionId} is not current");

        try
        {
            await SaveChangesAsync();
            await transaction.CommitAsync();
        }
        catch
        {
            RollbackTransaction();
            throw;
        }
        finally
        {
            if (HasActiveTransaction)
            {
                _currentTransaction.Dispose();
                _currentTransaction = null;
            }
        }
    }

    public void RollbackTransaction()
    {
        try
        {
            _currentTransaction?.Rollback();
        }
        finally
        {
            if (HasActiveTransaction)
            {
                _currentTransaction?.Dispose();
                _currentTransaction = null;
            }
        }
    }
}

#nullable enable
