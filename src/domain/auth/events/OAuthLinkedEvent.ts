import { DomainEvent } from '../../shared/DomainEvent'
import type { OAuthProvider } from '../value-objects/OAuthProfile'

export class OAuthLinkedEvent extends DomainEvent {
  readonly eventName = 'auth.user.oauth_linked'

  constructor(
    readonly userId: string,
    readonly provider: OAuthProvider,
    readonly providerEmail: string,
  ) {
    super()
  }
}
