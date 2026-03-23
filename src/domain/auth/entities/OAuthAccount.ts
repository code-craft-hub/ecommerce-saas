import type { OAuthProfile, OAuthProvider } from '../value-objects/OAuthProfile'

export interface OAuthAccountProps {
  id: string
  userId: string
  provider: OAuthProvider
  providerUserId: string
  email: string
  name: string
  pictureUrl: string | null
  providerMetadata: Record<string, unknown>
  linkedAt: Date
  lastLoginAt: Date | null
}

/**
 * OAuthAccount entity — represents a linked OAuth identity.
 * Belongs to UserAggregate but managed by OAuthAccountRepository.
 */
export class OAuthAccount {
  private constructor(private props: OAuthAccountProps) {}

  static reconstitute(props: OAuthAccountProps): OAuthAccount {
    return new OAuthAccount(props)
  }

  static create(params: {
    id: string
    userId: string
    profile: OAuthProfile
  }): OAuthAccount {
    return new OAuthAccount({
      id: params.id,
      userId: params.userId,
      provider: params.profile.provider,
      providerUserId: params.profile.providerUserId,
      email: params.profile.email,
      name: params.profile.name,
      pictureUrl: params.profile.pictureUrl,
      providerMetadata: params.profile.rawClaims,
      linkedAt: new Date(),
      lastLoginAt: null,
    })
  }

  get id(): string {
    return this.props.id
  }
  get userId(): string {
    return this.props.userId
  }
  get provider(): OAuthProvider {
    return this.props.provider
  }
  get providerUserId(): string {
    return this.props.providerUserId
  }
  get email(): string {
    return this.props.email
  }
  get name(): string {
    return this.props.name
  }
  get pictureUrl(): string | null {
    return this.props.pictureUrl
  }
  get providerMetadata(): Record<string, unknown> {
    return { ...this.props.providerMetadata }
  }
  get linkedAt(): Date {
    return this.props.linkedAt
  }
  get lastLoginAt(): Date | null {
    return this.props.lastLoginAt
  }

  recordLogin(profile: OAuthProfile): void {
    this.props.lastLoginAt = new Date()
    // Update profile claims that may have changed
    this.props.name = profile.name
    this.props.email = profile.email
    this.props.pictureUrl = profile.pictureUrl
    this.props.providerMetadata = profile.rawClaims
  }
}
