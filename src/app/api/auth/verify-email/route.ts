import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import { VerifyEmailRequestSchema } from '@/application/auth/verify/VerifyEmailUseCase'
import {
  errorResponse,
  successResponse,
} from '@/presentation/api/middleware/response'
import { getClientIp } from '@/presentation/api/middleware/authenticate'

/**
 * GET /api/auth/verify-email?token=...
 * Verify email address using the token from the verification email.
 */
export async function GET(req: NextRequest) {
  const token = req.nextUrl.searchParams.get('token')
  const parsed = VerifyEmailRequestSchema.safeParse({ token })
  if (!parsed.success) {
    return Response.json({ error: 'Invalid token' }, { status: 400 })
  }

  const { verifyEmailUseCase } = getContainer()
  const result = await verifyEmailUseCase.execute(parsed.data, {
    ipAddress: getClientIp(req) ?? undefined,
  })

  if (result.isErr()) return errorResponse(result.error)
  return successResponse(result.value)
}

/**
 * POST /api/auth/verify-email
 * Same as GET but accepts token in body (for API clients).
 */
export async function POST(req: NextRequest) {
  let body: unknown
  try {
    body = await req.json()
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  const parsed = VerifyEmailRequestSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json({ error: 'Invalid token' }, { status: 400 })
  }

  const { verifyEmailUseCase } = getContainer()
  const result = await verifyEmailUseCase.execute(parsed.data, {
    ipAddress: getClientIp(req) ?? undefined,
  })

  if (result.isErr()) return errorResponse(result.error)
  return successResponse(result.value)
}
