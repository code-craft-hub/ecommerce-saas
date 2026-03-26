/**
 * ABAC Policy Evaluator — Attribute-Based Access Control.
 *
 * Evaluates contextual signals that RBAC cannot express:
 *   - IP reputation (block suspicious/tor IPs)
 *   - Email verification requirement for sensitive operations
 *   - Account age gating (prevent new accounts from admin ops)
 *   - Failed login threshold (temporary lockout signal)
 *
 * ABAC can produce Deny (hard block) or NotApplicable (defer to RBAC).
 * It never produces Allow on its own — it enforces constraints.
 */

import type { IPolicyEvaluator } from '../../../domain/authz/services/IPolicyEvaluator'
import type { AuthorizationContext } from '../../../domain/authz/value-objects/AuthorizationContext'
import type { AuthorizationDecision } from '../../../domain/authz/types/AuthorizationDecision'
import { Deny, NotApplicable } from '../../../domain/authz/types/AuthorizationDecision'
import { Permission } from '../../../domain/authz/value-objects/Permission'

/** Permissions that require email verification before they can be exercised */
const EMAIL_VERIFICATION_REQUIRED: Permission[] = [
  Permission.USER_WRITE_SELF,
  Permission.USER_DELETE_SELF,
  Permission.SESSION_REVOKE_ANY,
  Permission.ROLE_ASSIGN,
  Permission.ROLE_REVOKE,
  Permission.AUDIT_READ,
  Permission.CONTENT_MODERATE,
]

/** Max failed login count before ABAC blocks access (separate from rate limiter) */
const FAILED_LOGIN_BLOCK_THRESHOLD = 10

/** Min account age in milliseconds before admin operations are permitted */
const ADMIN_MIN_ACCOUNT_AGE_MS = 7 * 24 * 60 * 60 * 1000 // 7 days

export class AbacPolicy implements IPolicyEvaluator {
  readonly name = 'ABAC'

  async evaluate(ctx: AuthorizationContext): Promise<AuthorizationDecision> {
    const { subject, action, environment } = ctx

    // Rule 1: Block known-bad IP addresses immediately
    if (environment.ipReputation === 'blocked') {
      return Deny(
        'IP address is blocklisted',
        'ABAC',
        { ipAddress: environment.ipAddress, ipReputation: environment.ipReputation },
      )
    }

    // Rule 2: Suspicious IP + sensitive action = deny
    if (
      environment.ipReputation === 'suspicious' &&
      !action.grants(Permission.USER_READ_SELF) // allow read-only from suspicious IPs
    ) {
      return Deny(
        'Suspicious IP address blocked for write/admin operations',
        'ABAC',
        { ipAddress: environment.ipAddress },
      )
    }

    // Rule 3: Email verification required for sensitive operations
    const requiresVerification = EMAIL_VERIFICATION_REQUIRED.some((p) =>
      p.grants(action),
    )
    if (requiresVerification && !subject.emailVerified) {
      return Deny(
        'Email verification required for this operation',
        'ABAC',
        { required: 'emailVerified', actual: false },
      )
    }

    // Rule 4: High failed login rate — temporary ABAC block
    if (environment.recentFailedLogins >= FAILED_LOGIN_BLOCK_THRESHOLD) {
      return Deny(
        `Account temporarily blocked — ${environment.recentFailedLogins} recent failed logins`,
        'ABAC',
        { recentFailedLogins: environment.recentFailedLogins },
      )
    }

    // Rule 5: Admin operations require minimum account age
    const isAdminAction = action.resource === 'admin' ||
      action.resource === 'role' ||
      action.action === 'any'
    const accountAgeMs = Date.now() - subject.createdAt.getTime()
    if (isAdminAction && accountAgeMs < ADMIN_MIN_ACCOUNT_AGE_MS) {
      return Deny(
        'Account must be at least 7 days old for administrative operations',
        'ABAC',
        {
          required: `${ADMIN_MIN_ACCOUNT_AGE_MS}ms`,
          actual: `${accountAgeMs}ms`,
        },
      )
    }

    return NotApplicable('No ABAC constraints violated', 'ABAC')
  }
}
