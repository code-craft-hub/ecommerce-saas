import type { DomainEvent } from '../../domain/shared/DomainEvent'

type EventHandler<T extends DomainEvent> = (event: T) => Promise<void>

/**
 * In-process event bus for domain event dispatch.
 * For production, replace with a message broker (Redis Pub/Sub, SQS, etc.)
 * while keeping the same interface.
 */
export class EventBus {
  private handlers = new Map<string, EventHandler<DomainEvent>[]>()

  subscribe<T extends DomainEvent>(
    eventName: string,
    handler: EventHandler<T>,
  ): void {
    const existing = this.handlers.get(eventName) ?? []
    this.handlers.set(eventName, [
      ...existing,
      handler as EventHandler<DomainEvent>,
    ])
  }

  async publish(events: ReadonlyArray<DomainEvent>): Promise<void> {
    for (const event of events) {
      const handlers = this.handlers.get(event.eventName) ?? []
      await Promise.all(handlers.map((h) => h(event)))
    }
  }

  async publishOne(event: DomainEvent): Promise<void> {
    return this.publish([event])
  }
}

// Singleton for application-wide event bus
// In Next.js, module singletons persist across requests in the same process
let _bus: EventBus | null = null
export function getEventBus(): EventBus {
  if (!_bus) _bus = new EventBus()
  return _bus
}
