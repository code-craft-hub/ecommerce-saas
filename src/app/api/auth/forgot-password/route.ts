import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import { ForgotPasswordRequestSchema } from '@/application/auth/password/ForgotPasswordUseCase'
import {
  errorResponse,
  successResponse,
} from '@/presentation/api/middleware/response'
import {
  checkRateLimit,
  rateLimitResponse,
} from '@/presentation/api/middleware/rateLimiter'
import { getClientIp } from '@/presentation/api/middleware/authenticate'

/**
 * POST /api/auth/forgot-password
 * Initiate password reset. Always returns success to prevent user enumeration.
 */
export async function POST(req: NextRequest) {
  let body: unknown
  try {
    body = await req.json()
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  const parsed = ForgotPasswordRequestSchema.safeParse(body)
  if (!parsed.success) {
    // Still return success — don't leak email validity
    return successResponse({ success: true })
  }

  // Rate limit by email to prevent spam
  const rl = await checkRateLimit(
    'password_reset',
    parsed.data.email.toLowerCase(),
  )
  if (!rl.allowed) return rateLimitResponse(rl.resetAt)

  const { forgotPasswordUseCase } = getContainer()
  const result = await forgotPasswordUseCase.execute(parsed.data, {
    ipAddress: getClientIp(req) ?? undefined,
  })

  // Always succeed — even if user doesn't exist
  if (result.isErr()) return successResponse({ success: true })
  return successResponse(result.value)
}
