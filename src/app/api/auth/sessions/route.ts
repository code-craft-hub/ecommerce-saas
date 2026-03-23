import type { NextRequest } from 'next/server'
import { getContainer } from '../../../../infrastructure/container'
import {
  requireAuth,
} from '../../../../presentation/api/middleware/authenticate'
import {
  errorResponse,
  successResponse,
} from '../../../../presentation/api/middleware/response'

/**
 * GET /api/auth/sessions
 * List all active sessions for the authenticated user.
 */
export async function GET(req: NextRequest) {
  const authResult = await requireAuth(req)
  if ('response' in authResult) return authResult.response

  const { ctx } = authResult

  // Current session ID can be identified via refresh token cookie
  // We pass the JTI of the current access token as a hint
  const { listSessionsUseCase } = getContainer()
  const result = await listSessionsUseCase.execute({
    userId: ctx.userId,
    currentSessionId: null, // TODO: pass actual RT ID from cookie
  })

  if (result.isErr()) return errorResponse(result.error)
  return successResponse(result.value)
}
