import { AggregateRoot } from '@/domain/shared/AggregateRoot'
import type { Email } from '@/domain/auth/value-objects/Email'
import type { HashedPassword } from '@/domain/auth/value-objects/Password'
import { UserCreatedEvent } from '@/domain/auth/events/UserCreatedEvent'
import { PasswordChangedEvent } from '@/domain/auth/events/PasswordChangedEvent'
import { OAuthLinkedEvent } from '@/domain/auth/events/OAuthLinkedEvent'
import type { OAuthProfile } from '@/domain/auth/value-objects/OAuthProfile'

export interface UserProps {
  id: string
  email: Email
  emailVerified: boolean
  passwordHash: HashedPassword | null
  passwordPepperVersion: number
  /** Increment to instantly invalidate ALL sessions */
  tokenVersion: number
  name: string
  createdAt: Date
  updatedAt: Date
  deletedAt: Date | null
  metadata: Record<string, unknown>
}

/**
 * User Aggregate Root.
 *
 * Invariants enforced:
 * - Email is always a valid Email VO
 * - tokenVersion is always non-negative
 * - Soft-deleted users cannot authenticate
 * - Password can only be set once (without explicit reset) for OAuth users
 */
export class User extends AggregateRoot {
  private constructor(private props: UserProps) {
    super()
  }

  // -------------------------------------------------------------------------
  // Factory method — use UserFactory for new users
  // -------------------------------------------------------------------------

  static reconstitute(props: UserProps): User {
    return new User(props)
  }

  static create(params: {
    id: string
    email: Email
    name: string
    passwordHash: HashedPassword | null
    pepperVersion: number
  }): User {
    const user = new User({
      id: params.id,
      email: params.email,
      emailVerified: false,
      passwordHash: params.passwordHash,
      passwordPepperVersion: params.pepperVersion,
      tokenVersion: 1,
      name: params.name,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
      metadata: {},
    })
    user.addDomainEvent(new UserCreatedEvent(params.id, params.email.value))
    return user
  }

  // -------------------------------------------------------------------------
  // Identity
  // -------------------------------------------------------------------------

  get id(): string {
    return this.props.id
  }
  get email(): Email {
    return this.props.email
  }
  get emailVerified(): boolean {
    return this.props.emailVerified
  }
  get name(): string {
    return this.props.name
  }
  get passwordHash(): HashedPassword | null {
    return this.props.passwordHash
  }
  get passwordPepperVersion(): number {
    return this.props.passwordPepperVersion
  }
  get tokenVersion(): number {
    return this.props.tokenVersion
  }
  get createdAt(): Date {
    return this.props.createdAt
  }
  get updatedAt(): Date {
    return this.props.updatedAt
  }
  get deletedAt(): Date | null {
    return this.props.deletedAt
  }
  get metadata(): Record<string, unknown> {
    return { ...this.props.metadata }
  }
  get isDeleted(): boolean {
    return this.props.deletedAt !== null
  }
  get hasPassword(): boolean {
    return this.props.passwordHash !== null
  }

  // -------------------------------------------------------------------------
  // Mutations (always emit events or update timestamps)
  // -------------------------------------------------------------------------

  verifyEmail(): void {
    this.props.emailVerified = true
    this.props.updatedAt = new Date()
  }

  setPassword(hash: HashedPassword, pepperVersion: number): void {
    this.props.passwordHash = hash
    this.props.passwordPepperVersion = pepperVersion
    this.props.updatedAt = new Date()
    this.addDomainEvent(new PasswordChangedEvent(this.props.id, false))
  }

  changePassword(hash: HashedPassword, pepperVersion: number): void {
    this.props.passwordHash = hash
    this.props.passwordPepperVersion = pepperVersion
    // Invalidate ALL sessions via token version bump
    this.props.tokenVersion += 1
    this.props.updatedAt = new Date()
    this.addDomainEvent(new PasswordChangedEvent(this.props.id, true))
  }

  /**
   * Revoke all active sessions instantly by bumping token version.
   * Any JWT with an older version is immediately invalid.
   */
  revokeAllSessions(): void {
    this.props.tokenVersion += 1
    this.props.updatedAt = new Date()
  }

  recordOAuthLink(profile: OAuthProfile): void {
    this.props.updatedAt = new Date()
    this.addDomainEvent(
      new OAuthLinkedEvent(this.props.id, profile.provider, profile.email),
    )
  }

  softDelete(): void {
    this.props.deletedAt = new Date()
    this.props.updatedAt = new Date()
  }
}
