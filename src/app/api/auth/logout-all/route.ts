import type { NextRequest } from 'next/server'
import { getContainer } from '../../../../infrastructure/container'
import {
  requireAuth,
  getClientIp,
  getUserAgent,
} from '../../../../presentation/api/middleware/authenticate'
import {
  errorResponse,
  successResponse,
  clearRefreshTokenCookie,
} from '../../../../presentation/api/middleware/response'

/**
 * POST /api/auth/logout-all
 * Invalidate all sessions across all devices.
 */
export async function POST(req: NextRequest) {
  const authResult = await requireAuth(req)
  if ('response' in authResult) return authResult.response

  const { ctx } = authResult
  const { logoutAllUseCase } = getContainer()

  const result = await logoutAllUseCase.execute(
    {
      userId: ctx.userId,
      currentAccessTokenJti: ctx.jti,
      currentAccessTokenExp: ctx.exp,
    },
    {
      ipAddress: getClientIp(req) ?? undefined,
      userAgent: getUserAgent(req) ?? undefined,
    },
  )

  if (result.isErr()) return errorResponse(result.error)

  const response = successResponse(result.value)
  const headers = new Headers(response.headers)
  headers.set('Set-Cookie', clearRefreshTokenCookie())
  return new Response(response.body, { status: 200, headers })
}
