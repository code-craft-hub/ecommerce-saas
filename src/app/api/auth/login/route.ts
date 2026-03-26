import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import { LoginRequestSchema } from '@/application/auth/login/LoginUseCase'
import {
  errorResponse,
  successResponse,
  setRefreshTokenCookie,
} from '@/presentation/api/middleware/response'
import {
  checkRateLimit,
  rateLimitResponse,
} from '@/presentation/api/middleware/rateLimiter'
import {
  getClientIp,
  getUserAgent,
} from '@/presentation/api/middleware/authenticate'

/**
 * POST /api/auth/login
 * Authenticate with email + password.
 * Returns: accessToken in body, refreshToken in httpOnly cookie.
 */
export async function POST(req: NextRequest) {
  const ip = getClientIp(req)

  let body: unknown
  try {
    body = await req.json()
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  const parsed = LoginRequestSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: 'Validation failed', details: parsed.error.flatten() },
      { status: 422 },
    )
  }

  // Rate limit per IP + email combo to prevent distributed brute force
  const rl = await checkRateLimit(
    'login',
    `${ip ?? 'unknown'}:${parsed.data.email.toLowerCase()}`,
  )
  if (!rl.allowed) return rateLimitResponse(rl.resetAt)

  const { loginUseCase } = getContainer()
  const result = await loginUseCase.execute(parsed.data, {
    ipAddress: ip ?? undefined,
    userAgent: getUserAgent(req) ?? undefined,
  })

  if (result.isErr()) return errorResponse(result.error)

  const { accessToken, refreshToken, user } = result.value

  // Access token in body, refresh token as httpOnly cookie
  const response = successResponse({ accessToken, user })
  const rtExpiry = new Date(
    Date.now() +
      Number(process.env.REFRESH_TOKEN_EXPIRY_DAYS ?? 30) * 86_400_000,
  )
  return setRefreshTokenCookie(response, refreshToken, rtExpiry)
}
