/**
 * CheckPermissionUseCase.
 *
 * The single entry point for all runtime permission checks in the application.
 * Orchestrates context assembly (PIP) → policy evaluation (PDP) → enforcement (PEP).
 *
 * Usage:
 *   const result = await checkPermission.execute({
 *     userId: ctx.userId,
 *     tokenVersion: ctx.tokenVersion,
 *     action: Permission.USER_WRITE_SELF,
 *     resource: { type: 'user', id: targetUserId, ownerId: targetUserId },
 *     environment: { ipAddress, userAgent },
 *   })
 *   if (result.isErr()) return forbidden()
 */

import { z } from 'zod'
import type { IUseCase } from '../../../domain/shared/IUseCase'
import { type Result, DomainError, ok, err } from '../../../domain/shared/Result'
import { Permission } from '../../../domain/authz/value-objects/Permission'
import { AuthorizationContext } from '../../../domain/authz/value-objects/AuthorizationContext'
import type { IAuthorizationService } from '../../../domain/authz/services/IAuthorizationService'
import type { IUserRoleRepository } from '../../../domain/authz/repositories/IUserRoleRepository'
import type { IUserRepository } from '../../../domain/auth/repositories/IUserRepository'

export const CheckPermissionRequestSchema = z.object({
  userId: z.string().uuid(),
  tokenVersion: z.number().int().positive(),
  action: z.string().min(1),
  resource: z.object({
    type: z.string(),
    id: z.string().nullable().default(null),
    ownerId: z.string().nullable().default(null),
    custom: z.record(z.string(), z.unknown()).default({}),
  }),
  environment: z.object({
    ipAddress: z.string().nullable().optional(),
    userAgent: z.string().nullable().optional(),
    deviceFingerprint: z.string().nullable().optional(),
  }).optional(),
})

export type CheckPermissionRequest = z.infer<typeof CheckPermissionRequestSchema>

export interface CheckPermissionResponse {
  allowed: boolean
  reason: string
  source: string
}

export class CheckPermissionUseCase
  implements IUseCase<CheckPermissionRequest, CheckPermissionResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly userRoleRepo: IUserRoleRepository,
    private readonly authzService: IAuthorizationService,
  ) {}

  async execute(
    input: CheckPermissionRequest,
  ): Promise<Result<CheckPermissionResponse>> {
    // 1. Load the user for subject attributes
    const user = await this.userRepo.findById(input.userId)
    if (!user || user.isDeleted) {
      return err(DomainError.userNotFound())
    }

    // 2. Validate token version (defense-in-depth: verify session is still valid)
    if (input.tokenVersion < user.tokenVersion) {
      return err(DomainError.tokenRevoked())
    }

    // 3. Load user's roles
    const roleAssignments = await this.userRoleRepo.findRolesForUser(input.userId)
    const roles = roleAssignments.map((a) => a.roleName)

    // Ensure every user has the default 'user' role even if not explicitly assigned
    if (roles.length === 0) roles.push('user')

    // 4. Parse the action permission
    let action: Permission
    try {
      action = Permission.of(input.action)
    } catch {
      return err(DomainError.internal(`Invalid permission format: ${input.action}`))
    }

    // 5. Build the authorization context
    const ctx = AuthorizationContext.create({
      subject: {
        userId: input.userId,
        roles,
        emailVerified: user.emailVerified,
        tokenVersion: user.tokenVersion,
        createdAt: user.createdAt,
      },
      action,
      resource: {
        type: input.resource.type,
        id: input.resource.id,
        ownerId: input.resource.ownerId,
        custom: input.resource.custom,
      },
      environment: {
        ipAddress: input.environment?.ipAddress ?? null,
        userAgent: input.environment?.userAgent ?? null,
        deviceFingerprint: input.environment?.deviceFingerprint ?? null,
      },
    })

    // 6. Delegate to PolicyEnforcementPoint (which calls PDP internally)
    const decisionResult = await this.authzService.authorize(ctx)
    if (decisionResult.isErr()) {
      // Infrastructure failure — fail closed
      return err(decisionResult.error)
    }

    const decision = decisionResult.value

    if (decision.effect !== 'Allow') {
      return err(
        DomainError.permissionDenied(input.action, input.resource.type),
      )
    }

    return ok({
      allowed: true,
      reason: decision.reason,
      source: decision.source,
    })
  }
}
