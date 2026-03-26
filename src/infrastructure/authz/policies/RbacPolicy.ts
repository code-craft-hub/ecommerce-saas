/**
 * RBAC Policy Evaluator.
 *
 * Resolves roles for the subject and checks whether any granted permission
 * satisfies the requested action.
 *
 * Algorithm:
 *   1. Load full Role objects for each role name on the subject
 *   2. For each role, check if any of its permissions .grants(required)
 *   3. If any role grants → Allow; otherwise → NotApplicable (no explicit deny)
 *
 * RBAC alone never Denies — it either Allows or defers to other frameworks.
 * Explicit Deny comes from PBAC/ABAC.
 */

import type { IPolicyEvaluator } from '../../../domain/authz/services/IPolicyEvaluator'
import type { AuthorizationContext } from '../../../domain/authz/value-objects/AuthorizationContext'
import type { AuthorizationDecision } from '../../../domain/authz/types/AuthorizationDecision'
import { Allow, NotApplicable } from '../../../domain/authz/types/AuthorizationDecision'
import type { IRoleRepository } from '../../../domain/authz/repositories/IRoleRepository'

export class RbacPolicy implements IPolicyEvaluator {
  readonly name = 'RBAC'

  constructor(private readonly roleRepo: IRoleRepository) {}

  async evaluate(ctx: AuthorizationContext): Promise<AuthorizationDecision> {
    const { subject, action } = ctx

    if (subject.roles.length === 0) {
      return NotApplicable('Subject has no roles assigned', 'RBAC')
    }

    // Load all roles in parallel
    const roleObjects = await Promise.all(
      subject.roles.map((name) => this.roleRepo.findByName(name)),
    )

    for (const role of roleObjects) {
      if (!role) continue
      if (role.hasPermission(action)) {
        return Allow(
          `Role '${role.name}' grants '${action.toString()}'`,
          'RBAC',
          { role: role.name, permission: action.toString() },
        )
      }
    }

    return NotApplicable(
      `No assigned role grants '${action.toString()}'`,
      'RBAC',
    )
  }
}
