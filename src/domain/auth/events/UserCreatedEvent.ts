import { DomainEvent } from '@/domain/shared/DomainEvent'

export class UserCreatedEvent extends DomainEvent {
  readonly eventName = 'auth.user.created'

  constructor(
    readonly userId: string,
    readonly email: string,
  ) {
    super()
  }
}
