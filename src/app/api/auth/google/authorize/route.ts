import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import { GoogleOAuthClient } from '@/infrastructure/services/GoogleOAuthClient'
import { checkRateLimit, rateLimitResponse } from '@/presentation/api/middleware/rateLimiter'
import { getClientIp } from '@/presentation/api/middleware/authenticate'

/**
 * GET /api/auth/google/authorize
 * Initiates OAuth 2.0 flow — redirects to Google consent screen.
 * State parameter protects against CSRF.
 */
export async function GET(req: NextRequest) {
  const ip = getClientIp(req)
  const rl = await checkRateLimit('oauth', ip ?? 'unknown')
  if (!rl.allowed) return rateLimitResponse(rl.resetAt)

  const { sessionCache } = getContainer()

  // Generate cryptographically random state token for CSRF protection
  const state = crypto.randomUUID()
  const prompt = req.nextUrl.searchParams.get('prompt') as
    | 'none'
    | 'consent'
    | 'select_account'
    | null

  // Store state in Redis with 10-minute TTL
  await sessionCache.setOAuthState(state, state, 600)

  const redirectUri =
    process.env.GOOGLE_REDIRECT_URI ??
    `${process.env.NEXT_PUBLIC_BASE_URL}/api/auth/google/callback`

  const googleClient = new GoogleOAuthClient({
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  })

  const authUrl = googleClient.buildAuthorizationUrl({
    redirectUri,
    state,
    prompt: prompt ?? undefined,
  })

  return Response.redirect(authUrl)
}
