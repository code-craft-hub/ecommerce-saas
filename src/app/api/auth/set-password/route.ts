import type { NextRequest } from 'next/server'
import { getContainer } from '../../../../infrastructure/container'
import { SetPasswordRequestSchema } from '../../../../application/auth/password/SetPasswordUseCase'
import {
  requireAuth,
  getClientIp,
} from '../../../../presentation/api/middleware/authenticate'
import { errorResponse, successResponse } from '../../../../presentation/api/middleware/response'

/**
 * POST /api/auth/set-password
 * Set initial password for OAuth-only users.
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

  const parsed = SetPasswordRequestSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json(
      { error: 'Validation failed', details: parsed.error.flatten() },
      { status: 422 },
    )
  }

  const { setPasswordUseCase } = getContainer()
  const result = await setPasswordUseCase.execute(
    { ...parsed.data, userId: ctx.userId },
    { ipAddress: getClientIp(req) ?? undefined },
  )

  if (result.isErr()) return errorResponse(result.error)
  return successResponse(result.value)
}
