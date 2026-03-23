/**
 * Base class for all domain events.
 * Domain events capture state transitions in the system.
 */

export abstract class DomainEvent {
  readonly occurredAt: Date
  readonly eventId: string

  constructor() {
    this.occurredAt = new Date()
    // Use crypto.randomUUID() — available in Node 16+ and modern browsers
    this.eventId = crypto.randomUUID()
  }

  abstract get eventName(): string
}
