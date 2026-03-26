import { DomainEvent } from '@/domain/shared/DomainEvent'

export class SessionRevokedEvent extends DomainEvent {
  readonly eventName = 'auth.session.revoked'

  constructor(
    readonly userId: string,
    readonly sessionsRevoked: number,
    readonly revokeAll: boolean,
  ) {
    super()
  }
}
