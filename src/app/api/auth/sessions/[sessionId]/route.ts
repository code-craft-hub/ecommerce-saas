import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import {
  requireAuth,
  getClientIp,
} from '@/presentation/api/middleware/authenticate'
import {
  errorResponse,
  successResponse,
} from '@/presentation/api/middleware/response'

/**
 * DELETE /api/auth/sessions/:sessionId
 * Revoke a specific session by ID.
 */
export async function DELETE(
  req: NextRequest,
  ctx: { params: Promise<{ sessionId: string }> },
) {
  const authResult = await requireAuth(req)
  if ('response' in authResult) return authResult.response

  const { ctx: auth } = authResult
  const { sessionId } = await ctx.params

  const { revokeSessionUseCase } = getContainer()
  const result = await revokeSessionUseCase.execute(
    {
      userId: auth.userId,
      sessionId,
    },
    { ipAddress: getClientIp(req) ?? undefined },
  )

  if (result.isErr()) return errorResponse(result.error)
  return successResponse(result.value)
}
