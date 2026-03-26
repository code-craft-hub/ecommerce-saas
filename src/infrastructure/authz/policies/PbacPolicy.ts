/**
 * PBAC Policy Evaluator — Policy-Based Access Control.
 *
 * Evaluates named, predefined company security policies.
 * Policies are coarse-grained, business-level rules that sit above RBAC/ABAC.
 *
 * Each policy has:
 *   - A name (for audit log, PAP management)
 *   - An applicability check (does this policy apply to this request?)
 *   - An evaluation function (Allow | Deny | NotApplicable)
 *
 * Policies are loaded from the PolicyAdministrationPoint and evaluated in
 * priority order. First explicit Deny wins (deny-overrides within PBAC).
 */

import type { IPolicyEvaluator } from '@/domain/authz/services/IPolicyEvaluator'
import type { AuthorizationContext } from '@/domain/authz/value-objects/AuthorizationContext'
import type {
  AuthorizationDecision,
  DecisionEffect,
} from '@/domain/authz/types/AuthorizationDecision'
import { Allow, Deny, NotApplicable } from '@/domain/authz/types/AuthorizationDecision'

// ---------------------------------------------------------------------------
// Policy definition interface
// ---------------------------------------------------------------------------

export interface PolicyDefinition {
  name: string
  priority: number
  /** Determines if this policy applies to the request context */
  isApplicable(ctx: AuthorizationContext): boolean
  /** Returns the policy decision */
  evaluate(ctx: AuthorizationContext): AuthorizationDecision
}

// ---------------------------------------------------------------------------
// Built-in predefined policies
// ---------------------------------------------------------------------------

/**
 * SuspiciousLoginPolicy: If this account has recent suspicious activity
 * (e.g. token reuse detected), block write operations until reviewed.
 */
const SuspiciousLoginPolicy: PolicyDefinition = {
  name: 'SuspiciousLoginPolicy',
  priority: 10,
  isApplicable(ctx) {
    // Applies to write/admin operations only
    return ctx.action.action !== 'read'
  },
  evaluate(ctx) {
    const suspiciousFlag = ctx.subject as unknown as { flaggedForReview?: boolean }
    if (suspiciousFlag.flaggedForReview) {
      return Deny(
        'Account flagged for security review — write access suspended',
        'PBAC',
        { policy: 'SuspiciousLoginPolicy' },
      )
    }
    return NotApplicable('SuspiciousLoginPolicy: no flag on account', 'PBAC')
  },
}

/**
 * AdminOperationAuditPolicy: Admin operations must always be allowed
 * only after audit capability is confirmed (future: real-time SIEM check).
 * For now this is a pass-through policy that documents the requirement.
 */
const AdminOperationAuditPolicy: PolicyDefinition = {
  name: 'AdminOperationAuditPolicy',
  priority: 20,
  isApplicable(ctx) {
    return ctx.action.resource === 'admin' || ctx.subject.roles.includes('admin')
  },
  evaluate(_ctx) {
    // All admin ops are permitted if RBAC allows — this policy is for future SIEM hooks
    return NotApplicable('AdminOperationAuditPolicy: audit integration pending', 'PBAC')
  },
}

/**
 * ServiceAccountReadOnlyPolicy: Service accounts can only perform read operations
 * unless explicitly granted write access via a scoped role.
 */
const ServiceAccountReadOnlyPolicy: PolicyDefinition = {
  name: 'ServiceAccountReadOnlyPolicy',
  priority: 30,
  isApplicable(ctx) {
    return ctx.subject.roles.includes('service')
  },
  evaluate(ctx) {
    if (ctx.action.action !== 'read' && ctx.action.action !== '*') {
      return Deny(
        'Service accounts are restricted to read-only operations by default',
        'PBAC',
        { policy: 'ServiceAccountReadOnlyPolicy', action: ctx.action.toString() },
      )
    }
    return NotApplicable('ServiceAccountReadOnlyPolicy: read action permitted', 'PBAC')
  },
}

// ---------------------------------------------------------------------------
// PbacPolicy evaluator
// ---------------------------------------------------------------------------

export class PbacPolicy implements IPolicyEvaluator {
  readonly name = 'PBAC'

  private readonly policies: PolicyDefinition[]

  constructor(additionalPolicies: PolicyDefinition[] = []) {
    this.policies = [
      SuspiciousLoginPolicy,
      AdminOperationAuditPolicy,
      ServiceAccountReadOnlyPolicy,
      ...additionalPolicies,
    ].sort((a, b) => a.priority - b.priority)
  }

  async evaluate(ctx: AuthorizationContext): Promise<AuthorizationDecision> {
    const applicable = this.policies.filter((p) => p.isApplicable(ctx))

    if (applicable.length === 0) {
      return NotApplicable('No PBAC policies applicable', 'PBAC')
    }

    // Deny-overrides: first Deny wins
    for (const policy of applicable) {
      const decision = policy.evaluate(ctx)
      if (decision.effect === 'Deny') {
        return decision
      }
    }

    return NotApplicable('All applicable PBAC policies passed', 'PBAC')
  }
}
