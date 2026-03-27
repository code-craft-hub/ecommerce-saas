import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import { GoogleOAuthClient } from '@/infrastructure/services/GoogleOAuthClient'
import { checkRateLimit, rateLimitResponse } from '@/presentation/api/middleware/rateLimiter'
import { getClientIp } from '@/presentation/api/middleware/authenticate'

/**
 * Generate a PKCE code_verifier (RFC 7636 §4.1).
 * 43–128 URL-safe characters from a cryptographically secure source.
 */
function generateCodeVerifier(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * Compute code_challenge = BASE64URL(SHA-256(verifier)) per RFC 7636 §4.2.
 */
async function computeCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * GET /api/auth/google/authorize
 * Initiates OAuth 2.0 + PKCE flow — redirects to Google consent screen.
 *
 * Security:
 * - state protects against CSRF
 * - code_challenge (S256) protects against authorization-code injection (RFC 9700)
 * - Both are stored together in Redis, consumed atomically on callback
 */
export async function GET(req: NextRequest) {
  const ip = getClientIp(req)
  const rl = await checkRateLimit('oauth', ip ?? 'unknown')
  if (!rl.allowed) return rateLimitResponse(rl.resetAt)

  const { sessionCache } = getContainer()

  // 1. Generate PKCE pair
  const codeVerifier = generateCodeVerifier()
  const codeChallenge = await computeCodeChallenge(codeVerifier)

  // 2. Generate CSRF state token
  const state = crypto.randomUUID()

  // 3. Store state + verifier together — consumed atomically in the callback
  //    The value is JSON so the use case can extract codeVerifier without
  //    an extra Redis round-trip.
  await sessionCache.setOAuthState(
    state,
    JSON.stringify({ state, codeVerifier }),
    600,
  )

  const prompt = req.nextUrl.searchParams.get('prompt') as
    | 'none'
    | 'consent'
    | 'select_account'
    | null

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
    codeChallenge,
    codeChallengeMethod: 'S256',
    prompt: prompt ?? undefined,
  })

  return Response.redirect(authUrl)
}
