/**
 * PolicyDecisionPoint (PDP).
 *
 * The central authorization decision engine. It aggregates decisions from
 * all registered policy evaluators using a configurable combining algorithm.
 *
 * Default algorithm: Deny-Overrides
 *   - Any Deny from any framework → final decision is Deny
 *   - At least one Allow and no Denies → final decision is Allow
 *   - All NotApplicable → final decision is Deny (fail-closed default)
 *
 * Framework evaluation order: PBAC → ABAC → RBAC → ReBAC
 *   PBAC and ABAC run first because they can produce hard Denies.
 *   RBAC is the primary allow mechanism.
 *   ReBAC supplements RBAC for resource-specific grants.
 *
 * The PDP is stateless and independently scalable.
 * All state is fetched by evaluators from their respective repositories.
 */

import type { IPolicyEvaluator } from '../../../domain/authz/services/IPolicyEvaluator'
import type { AuthorizationContext } from '../../../domain/authz/value-objects/AuthorizationContext'
import type { AuthorizationDecision } from '../../../domain/authz/types/AuthorizationDecision'
import { Allow, Deny } from '../../../domain/authz/types/AuthorizationDecision'

export type CombiningAlgorithm = 'deny-overrides' | 'permit-overrides' | 'first-applicable'

export class PolicyDecisionPoint {
  constructor(
    private readonly evaluators: IPolicyEvaluator[],
    private readonly algorithm: CombiningAlgorithm = 'deny-overrides',
  ) {}

  async decide(ctx: AuthorizationContext): Promise<AuthorizationDecision> {
    // Run all evaluators in parallel for performance
    const decisions = await Promise.all(
      this.evaluators.map((e) =>
        e.evaluate(ctx).catch(
          // Evaluator failure → treat as Deny (fail-closed)
          (error: unknown) => ({
            effect: 'Deny' as const,
            reason: `Policy evaluator '${e.name}' threw: ${String(error)}`,
            source: 'PDP' as const,
          }),
        ),
      ),
    )

    return this.combine(decisions, ctx)
  }

  private combine(
    decisions: AuthorizationDecision[],
    ctx: AuthorizationContext,
  ): AuthorizationDecision {
    switch (this.algorithm) {
      case 'deny-overrides':
        return this.denyOverrides(decisions, ctx)
      case 'permit-overrides':
        return this.permitOverrides(decisions, ctx)
      case 'first-applicable':
        return this.firstApplicable(decisions, ctx)
    }
  }

  /**
   * Deny-Overrides: any Deny wins. Fail-closed if all NotApplicable.
   */
  private denyOverrides(
    decisions: AuthorizationDecision[],
    ctx: AuthorizationContext,
  ): AuthorizationDecision {
    const denials = decisions.filter((d) => d.effect === 'Deny')
    if (denials.length > 0) {
      // Return the first denial with combined context
      return Deny(
        denials.map((d) => `[${d.source}] ${d.reason}`).join(' | '),
        'PDP',
        { action: ctx.action.toString(), resource: ctx.resource.type, denials },
      )
    }

    const allowances = decisions.filter((d) => d.effect === 'Allow')
    if (allowances.length > 0) {
      return Allow(
        allowances.map((d) => `[${d.source}] ${d.reason}`).join(' | '),
        'PDP',
        { action: ctx.action.toString(), resource: ctx.resource.type },
      )
    }

    // All NotApplicable — fail closed
    return Deny(
      `No policy granted '${ctx.action.toString()}' on '${ctx.resource.type}' — default deny`,
      'PDP',
      { action: ctx.action.toString(), resource: ctx.resource.type },
    )
  }

  /**
   * Permit-Overrides: any Allow wins. Still fails closed if all NotApplicable.
   */
  private permitOverrides(
    decisions: AuthorizationDecision[],
    ctx: AuthorizationContext,
  ): AuthorizationDecision {
    const allowances = decisions.filter((d) => d.effect === 'Allow')
    if (allowances.length > 0) {
      return Allow(
        allowances[0]!.reason,
        'PDP',
        { action: ctx.action.toString(), resource: ctx.resource.type },
      )
    }

    const denials = decisions.filter((d) => d.effect === 'Deny')
    if (denials.length > 0) {
      return Deny(denials[0]!.reason, 'PDP', {
        action: ctx.action.toString(),
        resource: ctx.resource.type,
      })
    }

    return Deny('Default deny — no applicable policy', 'PDP')
  }

  /**
   * First-Applicable: return the first non-NotApplicable decision.
   */
  private firstApplicable(
    decisions: AuthorizationDecision[],
    ctx: AuthorizationContext,
  ): AuthorizationDecision {
    const applicable = decisions.find((d) => d.effect !== 'NotApplicable')
    if (applicable) return applicable
    return Deny(
      `No applicable policy for '${ctx.action.toString()}' — default deny`,
      'PDP',
    )
  }
}
