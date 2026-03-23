import type { NextRequest } from 'next/server'
import { getContainer } from '../../../../infrastructure/container'
import { ResetPasswordRequestSchema } from '../../../../application/auth/password/ResetPasswordUseCase'
import {
  errorResponse,
  successResponse,
} from '../../../../presentation/api/middleware/response'
import { getClientIp } from '../../../../presentation/api/middleware/authenticate'

/**
 * POST /api/auth/reset-password
 * Complete password reset using token from email link.
 */
export async function POST(req: NextRequest) {
  let body: unknown
  try {
    body = await req.json()
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  const parsed = ResetPasswordRequestSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: 'Validation failed', details: parsed.error.flatten() },
      { status: 422 },
    )
  }

  const { resetPasswordUseCase } = getContainer()
  const result = await resetPasswordUseCase.execute(parsed.data, {
    ipAddress: getClientIp(req) ?? undefined,
  })

  if (result.isErr()) return errorResponse(result.error)
  return successResponse(result.value)
}
