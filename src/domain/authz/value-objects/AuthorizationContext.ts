/**
 * AuthorizationContext — the evaluation unit for every policy decision.
 *
 * Captures the full request context required for multi-framework authorization:
 *   - Subject:     who is requesting (RBAC, ABAC subject attributes)
 *   - Action:      what they want to do
 *   - Resource:    what they want to do it to (ReBAC, ABAC resource attributes)
 *   - Environment: contextual signals (ABAC environment attributes)
 *
 * This is the input to the PolicyDecisionPoint.
 */

import type { Permission } from './Permission'

// ---------------------------------------------------------------------------
// Subject Attributes (who)
// ---------------------------------------------------------------------------

export interface SubjectAttributes {
  /** Authenticated user ID */
  userId: string
  /** Assigned role names */
  roles: string[]
  /** Email verified state — required for sensitive operations */
  emailVerified: boolean
  /** Current token version — used to detect stale sessions */
  tokenVersion: number
  /** Account creation date — used for age-based policies */
  createdAt: Date
}

// ---------------------------------------------------------------------------
// Resource Attributes (what)
// ---------------------------------------------------------------------------

export interface ResourceAttributes {
  /** Resource type (e.g. 'user', 'session', 'order', 'post') */
  type: string
  /** Resource identifier */
  id: string | null
  /** Owner's user ID — used for ReBAC ownership checks */
  ownerId: string | null
  /** Custom attributes for ABAC evaluation */
  custom: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Environment Attributes (context)
// ---------------------------------------------------------------------------

export type IpReputation = 'clean' | 'suspicious' | 'blocked' | 'unknown'

export interface EnvironmentAttributes {
  /** Client IP address */
  ipAddress: string | null
  /** IP reputation score from threat intelligence */
  ipReputation: IpReputation
  /** Request timestamp */
  requestedAt: Date
  /** User agent string */
  userAgent: string | null
  /** Device fingerprint hash */
  deviceFingerprint: string | null
  /** Whether this IP has had recent failed logins */
  recentFailedLogins: number
}

// ---------------------------------------------------------------------------
// AuthorizationContext
// ---------------------------------------------------------------------------

export class AuthorizationContext {
  private constructor(
    readonly subject: SubjectAttributes,
    readonly action: Permission,
    readonly resource: ResourceAttributes,
    readonly environment: EnvironmentAttributes,
  ) {}

  static create(params: {
    subject: SubjectAttributes
    action: Permission
    resource: ResourceAttributes
    environment: Partial<EnvironmentAttributes>
  }): AuthorizationContext {
    const env: EnvironmentAttributes = {
      ipAddress: params.environment.ipAddress ?? null,
      ipReputation: params.environment.ipReputation ?? 'unknown',
      requestedAt: params.environment.requestedAt ?? new Date(),
      userAgent: params.environment.userAgent ?? null,
      deviceFingerprint: params.environment.deviceFingerprint ?? null,
      recentFailedLogins: params.environment.recentFailedLogins ?? 0,
    }
    return new AuthorizationContext(params.subject, params.action, params.resource, env)
  }

  /**
   * Convenience: is the acting user the owner of the target resource?
   */
  get isOwner(): boolean {
    return this.resource.ownerId === this.subject.userId
  }

  /**
   * Convenience: does the subject hold the named role?
   */
  hasRole(roleName: string): boolean {
    return this.subject.roles.includes(roleName)
  }
}
