import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import {
  errorResponse,
  successResponse,
  setRefreshTokenCookie,
} from '@/presentation/api/middleware/response'
import {
  checkRateLimit,
  rateLimitResponse,
} from '@/presentation/api/middleware/rateLimiter'
import { getClientIp } from '@/presentation/api/middleware/authenticate'

/**
 * POST /api/auth/refresh
 * Exchange a valid refresh token for a new token pair.
 * Implements rotation: old RT is invalidated, new RT issued.
 */
export async function POST(req: NextRequest) {
  const ip = getClientIp(req)

  // Get refresh token from httpOnly cookie (preferred) or body (API clients)
  let refreshToken = req.cookies.get('refresh_token')?.value

  if (!refreshToken) {
    try {
      const body = await req.json() as { refreshToken?: string }
      refreshToken = body.refreshToken
    } catch {
      // No body — that's fine
    }
  }

  if (!refreshToken) {
    return Response.json({ error: 'Refresh token required' }, { status: 400 })
  }

  // Rate limit refreshes per IP to prevent enumeration
  const rl = await checkRateLimit('refresh', ip ?? 'unknown')
  if (!rl.allowed) return rateLimitResponse(rl.resetAt)

  const { refreshTokenUseCase } = getContainer()
  const result = await refreshTokenUseCase.execute(
    { refreshToken },
    { ipAddress: ip ?? undefined },
  )

  if (result.isErr()) return errorResponse(result.error)

  const { accessToken, refreshToken: newRefreshToken } = result.value

  const response = successResponse({ accessToken })
  const rtExpiry = new Date(
    Date.now() +
      Number(process.env.REFRESH_TOKEN_EXPIRY_DAYS ?? 30) * 86_400_000,
  )
  return setRefreshTokenCookie(response, newRefreshToken, rtExpiry)
}
