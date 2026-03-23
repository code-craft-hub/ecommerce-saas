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
 * POST /api/auth/logout
 * Revoke current session.
 */
export async function POST(req: NextRequest) {
  const authResult = await requireAuth(req)
  if ('response' in authResult) return authResult.response

  const { ctx } = authResult
  const refreshToken = req.cookies.get('refresh_token')?.value ?? null

  const { logoutUseCase } = getContainer()
  const result = await logoutUseCase.execute(
    {
      userId: ctx.userId,
      accessTokenJti: ctx.jti,
      accessTokenExp: ctx.exp,
      refreshToken,
    },
    {
      ipAddress: getClientIp(req) ?? undefined,
      userAgent: getUserAgent(req) ?? undefined,
    },
  )

  if (result.isErr()) return errorResponse(result.error)

  const response = successResponse({ success: true })
  // Clear the refresh token cookie
  const headers = new Headers(response.headers)
  headers.set('Set-Cookie', clearRefreshTokenCookie())
  return new Response(response.body, { status: 200, headers })
}
