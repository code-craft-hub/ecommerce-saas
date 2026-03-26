/**
 * AuthorizationDecision — the output of a PolicyDecisionPoint evaluation.
 *
 * Every framework (RBAC, ABAC, PBAC, ReBAC) produces a Decision.
 * The PDP aggregates them via a configurable combining algorithm
 * (default: deny-overrides — any Deny wins).
 */

export type DecisionEffect = 'Allow' | 'Deny' | 'NotApplicable'

export interface AuthorizationDecision {
  effect: DecisionEffect
  /** Human-readable reason for the decision (logged in audit trail) */
  reason: string
  /** Which policy/framework produced this decision */
  source: 'RBAC' | 'ABAC' | 'PBAC' | 'ReBAC' | 'PDP'
  /** Optional metadata for observability */
  metadata?: Record<string, unknown>
}

export const Allow = (
  reason: string,
  source: AuthorizationDecision['source'],
  metadata?: Record<string, unknown>,
): AuthorizationDecision => ({ effect: 'Allow', reason, source, metadata })

export const Deny = (
  reason: string,
  source: AuthorizationDecision['source'],
  metadata?: Record<string, unknown>,
): AuthorizationDecision => ({ effect: 'Deny', reason, source, metadata })

export const NotApplicable = (
  reason: string,
  source: AuthorizationDecision['source'],
): AuthorizationDecision => ({ effect: 'NotApplicable', reason, source })
