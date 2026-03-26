/**
 * IPolicyEvaluator — interface for individual policy framework evaluators.
 *
 * Each framework (RBAC, ABAC, PBAC, ReBAC) implements this interface.
 * The PolicyDecisionPoint aggregates results from all evaluators.
 */

import type { AuthorizationContext } from '../value-objects/AuthorizationContext'
import type { AuthorizationDecision } from '../types/AuthorizationDecision'

export interface IPolicyEvaluator {
  readonly name: string
  evaluate(ctx: AuthorizationContext): Promise<AuthorizationDecision>
}
