import type { DomainEvent } from './DomainEvent'

/**
 * Aggregate Root base: collects domain events during state transitions.
 * Events are dispatched by the application layer after persistence.
 */
export abstract class AggregateRoot {
  private _domainEvents: DomainEvent[] = []

  get domainEvents(): ReadonlyArray<DomainEvent> {
    return this._domainEvents
  }

  protected addDomainEvent(event: DomainEvent): void {
    this._domainEvents.push(event)
  }

  clearDomainEvents(): void {
    this._domainEvents = []
  }
}
