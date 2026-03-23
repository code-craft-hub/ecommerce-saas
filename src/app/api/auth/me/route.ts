import type { NextRequest } from 'next/server'
import { getContainer } from '../../../../infrastructure/container'
import {
  requireAuth,
} from '../../../../presentation/api/middleware/authenticate'
import {
  errorResponse,
  successResponse,
} from '../../../../presentation/api/middleware/response'
import { DomainError } from '../../../../domain/shared/Result'

/**
 * GET /api/auth/me
 * Returns the authenticated user's profile.
 * Never put user data in the access token — always use this endpoint.
 */
export async function GET(req: NextRequest) {
  const authResult = await requireAuth(req)
  if ('response' in authResult) return authResult.response

  const { ctx } = authResult
  const { userRepo, oauthAccountRepo } = getContainer()

  const user = await userRepo.findById(ctx.userId)
  if (!user || user.isDeleted) {
    return errorResponse(DomainError.userNotFound())
  }

  const linkedAccounts = await oauthAccountRepo.findByUserId(user.id)

  return successResponse({
    id: user.id,
    email: user.email.value,
    name: user.name,
    emailVerified: user.emailVerified,
    hasPassword: user.hasPassword,
    linkedProviders: linkedAccounts.map((a) => ({
      provider: a.provider,
      email: a.email,
      name: a.name,
      linkedAt: a.linkedAt,
    })),
    createdAt: user.createdAt,
  })
}
