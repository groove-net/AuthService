using Microsoft.Extensions.DependencyInjection;

public interface IDomainEventDispatcher
{
    Task DispatchDomainEventsAsync(IEnumerable<Entity> entities, CancellationToken ct);
}

public class DomainEventDispatcher : IDomainEventDispatcher
{
    private readonly IServiceProvider _serviceProvider;

    public DomainEventDispatcher(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task DispatchDomainEventsAsync(IEnumerable<Entity> entities, CancellationToken ct)
    {
        var entityList = entities.ToList();
        var events = entityList.SelectMany(x => x.DomainEvents).ToList();

        // Clear events immediately to prevent double-firing
        entityList.ForEach(e => e.ClearDomainEvents());

        foreach (var domainEvent in events)
        {
            // Resolve the handler type: IDomainEventHandler<ActualEventType>
            var handlerType = typeof(IDomainEventHandler<>).MakeGenericType(domainEvent.GetType());
            var handlers = _serviceProvider.GetServices(handlerType);

            foreach (var handler in handlers)
            {
                // Invoke the "Handle" method
                var method = handlerType.GetMethod("Handle");
                await (Task)method!.Invoke(handler, new object[] { domainEvent, ct })!;
            }
        }
    }
}
