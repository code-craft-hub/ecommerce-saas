import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import { ResolveIdentityRequestSchema } from '@/application/auth/auth-methods/ResolveIdentityUseCase'
import { checkRateLimit, rateLimitResponse } from '@/presentation/api/middleware/rateLimiter'
import { getClientIp } from '@/presentation/api/middleware/authenticate'

/**
 * POST /api/auth/identity
 *
 * Given an email, returns which sign-in methods are available so the login
 * UI can show the correct form without an extra round-trip after the user
 * submits their email.
 *
 * Rate-limited to prevent email enumeration at scale.
 */
export async function POST(req: NextRequest) {
  const ip = getClientIp(req)
  const rl = await checkRateLimit('login', ip ?? 'unknown')
  if (!rl.allowed) return rateLimitResponse(rl.resetAt)

  let body: unknown
  try {
    body = await req.json()
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  const parsed = ResolveIdentityRequestSchema.safeParse(body)
  if (!parsed.success) {
    return Response.json({ error: 'Invalid email' }, { status: 422 })
  }

  const { resolveIdentityUseCase } = getContainer()
  const result = await resolveIdentityUseCase.execute(parsed.data)

  // Always return 200 — never expose whether the email exists via HTTP status
  return Response.json(result.isOk() ? result.value : { accountExists: false, availableMethods: [], suggestedMethod: null })
}
