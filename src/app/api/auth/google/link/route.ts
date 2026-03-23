import type { NextRequest } from 'next/server'
import { getContainer } from '../../../../../infrastructure/container'
import {
  requireAuth,
  getClientIp,
} from '../../../../../presentation/api/middleware/authenticate'
import {
  errorResponse,
  successResponse,
} from '../../../../../presentation/api/middleware/response'

/**
 * POST /api/auth/google/link
 * Link Google account to an existing authenticated user.
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

  const { code, state } = body as { code?: string; state?: string }
  if (!code || !state) {
    return Response.json({ error: 'code and state are required' }, { status: 400 })
  }

  const redirectUri =
    process.env.GOOGLE_REDIRECT_URI ??
    `${process.env.NEXT_PUBLIC_BASE_URL}/api/auth/google/callback`

  const { linkOAuthAccountUseCase } = getContainer()
  const result = await linkOAuthAccountUseCase.execute(
    {
      userId: ctx.userId,
      code,
      state,
      redirectUri,
    },
    { ipAddress: getClientIp(req) ?? undefined },
  )

  if (result.isErr()) return errorResponse(result.error)
  return successResponse(result.value)
}
