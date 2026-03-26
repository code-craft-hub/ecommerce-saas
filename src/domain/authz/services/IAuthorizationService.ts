/**
 * IAuthorizationService — domain-level authorization contract.
 *
 * Implemented by PolicyEnforcementPoint in the infrastructure layer.
 * This is the single entry point for all authorization decisions.
 * Domain and application layers depend only on this interface.
 */

import type { Result } from '../../shared/Result'
import type { DomainError } from '../../shared/Result'
import type { AuthorizationContext } from '../value-objects/AuthorizationContext'
import type { AuthorizationDecision } from '../types/AuthorizationDecision'

export interface IAuthorizationService {
  /**
   * Evaluate whether the subject in `ctx` is permitted to perform `ctx.action`
   * on `ctx.resource`, given `ctx.environment`.
   *
   * Returns Ok(decision) if the check ran successfully (even if denied).
   * Returns Err only for infrastructure failures (Redis down, DB error).
   */
  authorize(ctx: AuthorizationContext): Promise<Result<AuthorizationDecision, DomainError>>

  /**
   * Convenience helper: returns true if authorized, false if denied.
   * Swallows infrastructure errors as deny (fail-closed).
   */
  isAuthorized(ctx: AuthorizationContext): Promise<boolean>
}
