import type { NextRequest } from 'next/server'
import { getContainer } from '../../../../infrastructure/container'
import { ChangePasswordRequestSchema } from '../../../../application/auth/password/ChangePasswordUseCase'
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
 * POST /api/auth/change-password
 * Change password for authenticated users.
 * Invalidates all sessions except current (bumps token_version).
 */
export async function POST(req: NextRequest) {
  const authResult = await requireAuth(req)
  if ('response' in authResult) return authResult.response

  const { ctx } = authResult

  let body: unknown
  try {
    body = await req.json()
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  const parsed = ChangePasswordRequestSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: 'Validation failed', details: parsed.error.flatten() },
      { status: 422 },
    )
  }

  const { changePasswordUseCase } = getContainer()
  const result = await changePasswordUseCase.execute(
    {
      ...parsed.data,
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

  // Clear cookies since all sessions were invalidated
  const response = successResponse(result.value)
  const headers = new Headers(response.headers)
  headers.set('Set-Cookie', clearRefreshTokenCookie())
  return new Response(response.body, { status: 200, headers })
}
