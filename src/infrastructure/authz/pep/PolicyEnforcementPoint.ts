/**
 * PolicyEnforcementPoint (PEP) — implements IAuthorizationService.
 *
 * The thin enforcement layer that:
 *   1. Calls PIP to enrich the context with runtime attributes
 *   2. Delegates to PDP for the authorization decision
 *   3. Returns the decision back to callers
 *
 * The PEP is deliberately thin — no policy logic lives here.
 * It is the domain-layer entry point for all authorization checks.
 *
 * Security note: The PEP fails closed. Any infrastructure error results
 * in a Deny decision, never a false Allow.
 */

import type { IAuthorizationService } from '../../../domain/authz/services/IAuthorizationService'
import type { AuthorizationContext } from '../../../domain/authz/value-objects/AuthorizationContext'
import type { AuthorizationDecision } from '../../../domain/authz/types/AuthorizationDecision'
import { Deny } from '../../../domain/authz/types/AuthorizationDecision'
import { type Result, ok, err, DomainError } from '../../../domain/shared/Result'
import type { PolicyDecisionPoint } from '../pdp/PolicyDecisionPoint'
import type { PolicyInformationPoint } from '../pip/PolicyInformationPoint'
import { AuthorizationContext as AC } from '../../../domain/authz/value-objects/AuthorizationContext'

export class PolicyEnforcementPoint implements IAuthorizationService {
  constructor(
    private readonly pdp: PolicyDecisionPoint,
    private readonly pip: PolicyInformationPoint,
  ) {}

  async authorize(
    ctx: AuthorizationContext,
  ): Promise<Result<AuthorizationDecision, DomainError>> {
    try {
      // 1. Enrich context with PIP attributes (roles, IP reputation, failed logins)
      const enriched = await this.pip.enrich(
        ctx.subject.userId,
        ctx.environment.ipAddress,
      )

      // 2. Rebuild context with enriched attributes (PIP fills what JWT doesn't have)
      const enrichedCtx = AC.create({
        subject: {
          ...ctx.subject,
          roles: enriched.roles,
        },
        action: ctx.action,
        resource: ctx.resource,
        environment: {
          ...ctx.environment,
          ipReputation: enriched.ipReputation,
          recentFailedLogins: enriched.recentFailedLogins,
        },
      })

      // 3. Delegate to PDP
      const decision = await this.pdp.decide(enrichedCtx)
      return ok(decision)
    } catch (error) {
      // Infrastructure failure → fail closed (deny)
      return err(
        DomainError.internal(
          `Authorization infrastructure failure: ${String(error)}`,
        ),
      )
    }
  }

  async isAuthorized(ctx: AuthorizationContext): Promise<boolean> {
    try {
      const result = await this.authorize(ctx)
      if (result.isErr()) return false
      return result.value.effect === 'Allow'
    } catch {
      return false // fail closed
    }
  }
}
