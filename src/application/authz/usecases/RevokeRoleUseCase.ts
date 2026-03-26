/**
 * RevokeRoleUseCase.
 *
 * Removes a role from a user. Requires role:revoke permission.
 * Cannot revoke the 'user' base role (structural invariant).
 */

import { z } from 'zod'
import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, ok, err } from '@/domain/shared/Result'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IUserRoleRepository } from '@/domain/authz/repositories/IUserRoleRepository'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'

export const RevokeRoleRequestSchema = z.object({
  actorId: z.string().uuid(),
  targetUserId: z.string().uuid(),
  roleName: z.string().min(1).max(64),
})

export type RevokeRoleRequest = z.infer<typeof RevokeRoleRequestSchema>

export interface RevokeRoleResponse {
  userId: string
  roleName: string
  revokedAt: Date
}

export class RevokeRoleUseCase
  implements IUseCase<RevokeRoleRequest, RevokeRoleResponse>
{
  /** The base role every registered user must retain */
  private static readonly BASE_ROLE = 'user'

  constructor(
    private readonly userRepo: IUserRepository,
    private readonly userRoleRepo: IUserRoleRepository,
    private readonly auditLog: IAuditLogRepository,
  ) {}

  async execute(input: RevokeRoleRequest): Promise<Result<RevokeRoleResponse>> {
    // Cannot revoke the structural base role
    if (input.roleName === RevokeRoleUseCase.BASE_ROLE) {
      return err(DomainError.forbidden())
    }

    const target = await this.userRepo.findById(input.targetUserId)
    if (!target || target.isDeleted) return err(DomainError.userNotFound())

    const hasRole = await this.userRoleRepo.hasRole(
      input.targetUserId,
      input.roleName,
    )
    if (!hasRole) return err(DomainError.roleNotFound(input.roleName))

    await this.userRoleRepo.revoke(input.targetUserId, input.roleName)

    const revokedAt = new Date()

    await this.auditLog.log({
      userId: input.actorId,
      eventType: 'role_revoked' as never,
      ipAddress: null,
      userAgent: null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: { targetUserId: input.targetUserId, roleName: input.roleName },
    })

    return ok({ userId: input.targetUserId, roleName: input.roleName, revokedAt })
  }
}
