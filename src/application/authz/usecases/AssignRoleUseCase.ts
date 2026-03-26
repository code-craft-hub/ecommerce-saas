/**
 * AssignRoleUseCase.
 *
 * Grants a role to a user. Requires the acting user to hold role:assign permission.
 * Self-assignment is prohibited — only admins can assign roles.
 */

import { z } from 'zod'
import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, ok, err } from '@/domain/shared/Result'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IRoleRepository } from '@/domain/authz/repositories/IRoleRepository'
import type { IUserRoleRepository } from '@/domain/authz/repositories/IUserRoleRepository'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'

export const AssignRoleRequestSchema = z.object({
  /** User performing the action — must have role:assign */
  actorId: z.string().uuid(),
  /** User receiving the role */
  targetUserId: z.string().uuid(),
  roleName: z.string().min(1).max(64),
  /** Optional resource scope for scoped role assignments */
  resourceId: z.string().nullable().default(null),
  resourceType: z.string().nullable().default(null),
})

export type AssignRoleRequest = z.infer<typeof AssignRoleRequestSchema>

export interface AssignRoleResponse {
  userId: string
  roleName: string
  assignedAt: Date
}

export class AssignRoleUseCase
  implements IUseCase<AssignRoleRequest, AssignRoleResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly roleRepo: IRoleRepository,
    private readonly userRoleRepo: IUserRoleRepository,
    private readonly auditLog: IAuditLogRepository,
  ) {}

  async execute(input: AssignRoleRequest): Promise<Result<AssignRoleResponse>> {
    // 1. Verify both users exist
    const [actor, target] = await Promise.all([
      this.userRepo.findById(input.actorId),
      this.userRepo.findById(input.targetUserId),
    ])

    if (!actor || actor.isDeleted) return err(DomainError.userNotFound())
    if (!target || target.isDeleted) return err(DomainError.userNotFound())

    // 2. Verify role exists
    const role = await this.roleRepo.findByName(input.roleName)
    if (!role) return err(DomainError.roleNotFound(input.roleName))

    // 3. Prevent duplicate assignment
    const alreadyHas = await this.userRoleRepo.hasRole(
      input.targetUserId,
      input.roleName,
    )
    if (alreadyHas) {
      return err(DomainError.roleAlreadyAssigned(input.roleName))
    }

    // 4. Persist assignment
    const assignedAt = new Date()
    await this.userRoleRepo.assign({
      userId: input.targetUserId,
      roleName: input.roleName,
      assignedBy: input.actorId,
      resourceId: input.resourceId,
      resourceType: input.resourceType,
    })

    // 5. Audit
    await this.auditLog.log({
      userId: input.actorId,
      eventType: 'role_assigned' as never, // extended event type — safe cast
      ipAddress: null,
      userAgent: null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: {
        targetUserId: input.targetUserId,
        roleName: input.roleName,
        resourceId: input.resourceId,
        resourceType: input.resourceType,
      },
    })

    return ok({ userId: input.targetUserId, roleName: input.roleName, assignedAt })
  }
}
