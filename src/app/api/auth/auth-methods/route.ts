import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import { requireAuth } from '@/presentation/api/middleware/authenticate'
import { errorResponse, successResponse } from '@/presentation/api/middleware/response'

/**
 * GET /api/auth/auth-methods
 *
 * Returns all sign-in methods configured on the authenticated user's account
 * (equivalent to Google's "How you sign in" panel).
 */
export async function GET(req: NextRequest) {
  const authResult = await requireAuth(req)
  if ('response' in authResult) return authResult.response

  const { ctx } = authResult
  const { getAvailableAuthMethodsUseCase } = getContainer()

  const result = await getAvailableAuthMethodsUseCase.execute({ userId: ctx.userId })
  if (result.isErr()) return errorResponse(result.error)
  return successResponse(result.value)
}
