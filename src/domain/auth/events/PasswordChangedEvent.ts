import { DomainEvent } from '../../shared/DomainEvent'

export class PasswordChangedEvent extends DomainEvent {
  readonly eventName = 'auth.user.password_changed'

  /**
   * @param allSessionsInvalidated - true on changePassword, false on initial setPassword
   */
  constructor(
    readonly userId: string,
    readonly allSessionsInvalidated: boolean,
  ) {
    super()
  }
}
