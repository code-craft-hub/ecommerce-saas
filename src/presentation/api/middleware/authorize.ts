/**
 * Authorization middleware for Next.js API route handlers.
 *
 * Provides thin enforcement helpers that wrap the PolicyEnforcementPoint.
 * Route handlers call these after requireAuth(), passing the AuthContext.
 *
 * Defense-in-depth: auth context is verified again inside each check —
 * never trust middleware state alone (CVE-2025-29927 mitigation).
 *
 * Usage:
 *
 *   // In a route handler:
 *   const authResult = await requireAuth(req)
 *   if ('response' in authResult) return authResult.response
 *   const { ctx } = authResult
 *
 *   const authzResult = await requirePermission(ctx, Permission.USER_WRITE_SELF, {
 *     type: 'user',
 *     id: ctx.userId,
 *     ownerId: ctx.userId,
 *   }, req)
 *   if ('response' in authzResult) return authzResult.response
 */

import type { NextRequest } from 'next/server'
import type { AuthContext } from './authenticate'
import { getClientIp, getUserAgent } from './authenticate'
import { getContainer } from '../../../infrastructure/container'
import { Permission } from '../../../domain/authz/value-objects/Permission'
import { AuthorizationContext } from '../../../domain/authz/value-objects/AuthorizationContext'

export type { Permission }

interface ResourceDescriptor {
  type: string
  id: string | null
  ownerId: string | null
  custom?: Record<string, unknown>
}

type AuthzSuccess = { ctx: AuthContext }
type AuthzFailure = { response: Response }
type AuthzResult = AuthzSuccess | AuthzFailure

/**
 * Check that the authenticated user holds a specific permission,
 * evaluated against the given resource.
 *
 * Fails closed: any error → 403.
 */
export async function requirePermission(
  authCtx: AuthContext,
  permission: Permission,
  resource: ResourceDescriptor,
  req: NextRequest,
): Promise<AuthzResult> {
  const container = getContainer()

  const ipAddress = getClientIp(req)
  const userAgent = getUserAgent(req)

  try {
    const ctx = AuthorizationContext.create({
      subject: {
        userId: authCtx.userId,
        roles: [], // PEP/PIP will fill roles from DB
        emailVerified: false, // PEP/PIP will fill from DB
        tokenVersion: authCtx.tokenVersion,
        createdAt: new Date(0), // PEP will load from DB
      },
      action: permission,
      resource: {
        type: resource.type,
        id: resource.id,
        ownerId: resource.ownerId,
        custom: resource.custom ?? {},
      },
      environment: { ipAddress, userAgent },
    })

    const allowed = await container.authzService.isAuthorized(ctx)

    if (!allowed) {
      return {
        response: Response.json(
          {
            error: 'Permission denied',
            code: 'PERMISSION_DENIED',
            action: permission.toString(),
            resource: resource.type,
          },
          { status: 403 },
        ),
      }
    }

    return { ctx: authCtx }
  } catch {
    return {
      response: Response.json(
        { error: 'Authorization check failed', code: 'INTERNAL_ERROR' },
        { status: 500 },
      ),
    }
  }
}

/**
 * Check that the authenticated user holds a specific role.
 * This is a lightweight RBAC check that bypasses the full PDP pipeline
 * — useful for coarse-grained route guards (e.g. admin-only routes).
 */
export async function requireRole(
  authCtx: AuthContext,
  roleName: string,
  req: NextRequest,
): Promise<AuthzResult> {
  const container = getContainer()

  try {
    const assignments = await container.userRoleRepo.findRolesForUser(authCtx.userId)
    const roles = assignments.map((a) => a.roleName)

    if (!roles.includes(roleName)) {
      return {
        response: Response.json(
          {
            error: `Role '${roleName}' required`,
            code: 'FORBIDDEN',
          },
          { status: 403 },
        ),
      }
    }

    return { ctx: authCtx }
  } catch {
    return {
      response: Response.json(
        { error: 'Authorization check failed', code: 'INTERNAL_ERROR' },
        { status: 500 },
      ),
    }
  }
}
