/**
 * ReBAC Policy Evaluator — Relationship-Based Access Control.
 *
 * Evaluates resource ownership and group membership relationships.
 * Answers: "Does the subject have the required relation to the target resource?"
 *
 * Examples:
 *   user:alice owns post:123   → alice can edit/delete post 123
 *   user:alice member org:acme → alice can access acme resources
 *
 * ReBAC produces Allow when a relevant relationship exists.
 * It produces NotApplicable when no relationship is found (defers to RBAC).
 *
 * NOTE: ReBAC complements RBAC — it does not replace it.
 * If RBAC already grants (e.g. admin:*), ReBAC is not needed.
 * ReBAC is most useful for resource-specific grants below role level.
 */

import type { IPolicyEvaluator } from '@/domain/authz/services/IPolicyEvaluator'
import type { AuthorizationContext } from '@/domain/authz/value-objects/AuthorizationContext'
import type { AuthorizationDecision } from '@/domain/authz/types/AuthorizationDecision'
import { Allow, NotApplicable } from '@/domain/authz/types/AuthorizationDecision'
import type { IResourceRelationRepository } from '@/domain/authz/repositories/IResourceRelationRepository'
import type { RelationType } from '@/domain/authz/repositories/IResourceRelationRepository'

/**
 * Maps a requested action+scope to the minimum ReBAC relation required.
 * e.g. 'write' on a resource requires 'editor' or 'owner' or 'admin' relation.
 */
function requiredRelation(action: string, scope: string | null): RelationType[] {
  switch (action) {
    case 'read':
      return ['viewer', 'editor', 'owner', 'admin', 'member']
    case 'write':
      return ['editor', 'owner', 'admin']
    case 'delete':
      return ['owner', 'admin']
    case 'admin':
      return ['admin']
    default:
      // 'self' scope → always check ownership
      if (scope === 'self') return ['owner']
      return ['owner', 'admin']
  }
}

export class RebacPolicy implements IPolicyEvaluator {
  readonly name = 'ReBAC'

  constructor(
    private readonly relationRepo: IResourceRelationRepository,
  ) {}

  async evaluate(ctx: AuthorizationContext): Promise<AuthorizationDecision> {
    const { subject, action, resource } = ctx

    // ReBAC only applies when there's a concrete resource to check
    if (!resource.id || !resource.type) {
      return NotApplicable('No concrete resource to check relations for', 'ReBAC')
    }

    // Fast path: subject is the owner (stored on resource attributes)
    if (resource.ownerId === subject.userId) {
      return Allow(
        `Subject is owner of ${resource.type}:${resource.id}`,
        'ReBAC',
        { relation: 'owner', resourceType: resource.type, resourceId: resource.id },
      )
    }

    // Check each candidate relation type against the relation store
    const candidates = requiredRelation(action.action, action.scope)

    const checks = await Promise.all(
      candidates.map((rel) =>
        this.relationRepo.hasRelation(
          subject.userId,
          rel,
          resource.type,
          resource.id!,
        ),
      ),
    )

    const matchedIndex = checks.findIndex(Boolean)
    if (matchedIndex !== -1) {
      const matchedRelation = candidates[matchedIndex]!
      return Allow(
        `Subject has '${matchedRelation}' relation to ${resource.type}:${resource.id}`,
        'ReBAC',
        {
          relation: matchedRelation,
          resourceType: resource.type,
          resourceId: resource.id,
        },
      )
    }

    return NotApplicable(
      `No ReBAC relation found for ${subject.userId} → ${resource.type}:${resource.id}`,
      'ReBAC',
    )
  }
}
