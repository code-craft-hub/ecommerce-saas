import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import { requireAuth, getClientIp } from '@/presentation/api/middleware/authenticate'
import { errorResponse, successResponse } from '@/presentation/api/middleware/response'
import type { OAuthProvider } from '@/domain/auth/value-objects/OAuthProfile'

/**
 * DELETE /api/auth/google/unlink
 *
 * Remove the Google OAuth account linked to the authenticated user.
 * Enforces the orphan-prevention invariant: fails if this is the only
 * sign-in method (user must set a password first).
 */
export async function DELETE(req: NextRequest) {
  const authResult = await requireAuth(req)
  if ('response' in authResult) return authResult.response

  const { ctx } = authResult
  const { unlinkOAuthAccountUseCase } = getContainer()

  const result = await unlinkOAuthAccountUseCase.execute(
    { userId: ctx.userId, provider: 'google' as OAuthProvider },
    { ipAddress: getClientIp(req) ?? undefined },
  )

  if (result.isErr()) return errorResponse(result.error)
  return successResponse(result.value)
}
