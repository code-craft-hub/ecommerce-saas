import { DomainEvent } from '../../shared/DomainEvent'

export type AuthMethod = 'password' | 'google' | 'github' | 'microsoft'

export class UserAuthenticatedEvent extends DomainEvent {
  readonly eventName = 'auth.user.authenticated'

  constructor(
    readonly userId: string,
    readonly method: AuthMethod,
    readonly ipAddress: string | null,
    readonly userAgent: string | null,
    readonly riskLevel: 'low' | 'medium' | 'high',
  ) {
    super()
  }
}
