import type { NextRequest } from 'next/server'
import { getContainer } from '../../../../infrastructure/container'
import {
  SignupRequestSchema,
} from '../../../../application/auth/signup/SignupUseCase'
import {
  errorResponse,
  successResponse,
  setRefreshTokenCookie,
} from '../../../../presentation/api/middleware/response'
import {
  checkRateLimit,
  rateLimitResponse,
} from '../../../../presentation/api/middleware/rateLimiter'
import { getClientIp, getUserAgent } from '../../../../presentation/api/middleware/authenticate'

/**
 * POST /api/auth/signup
 * Register a new user with email + password.
 */
export async function POST(req: NextRequest) {
  const ip = getClientIp(req)

  // Rate limit by IP
  const rl = await checkRateLimit('signup', ip ?? 'unknown')
  if (!rl.allowed) return rateLimitResponse(rl.resetAt)

  let body: unknown
  try {
    body = await req.json()
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  const parsed = SignupRequestSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: 'Validation failed', details: parsed.error.flatten() },
      { status: 422 },
    )
  }

  const { signupUseCase } = getContainer()
  const result = await signupUseCase.execute(parsed.data, {
    ipAddress: ip ?? undefined,
    userAgent: getUserAgent(req) ?? undefined,
  })

  if (result.isErr()) return errorResponse(result.error)

  const { accessToken, user } = result.value

  // Access token goes in the response body (for SPA clients)
  // Refresh token is set as httpOnly cookie by the client caller
  // Note: signup doesn't have a refresh token in the response (only access token)
  // The full refresh token is issued during login
  const response = successResponse({ accessToken, user }, 201)
  return response
}
