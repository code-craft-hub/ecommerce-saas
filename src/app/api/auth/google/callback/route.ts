import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import {
  setRefreshTokenCookie,
  setAccessTokenCookie,
} from '@/presentation/api/middleware/response'
import {
  getClientIp,
  getUserAgent,
} from '@/presentation/api/middleware/authenticate'

/**
 * GET /api/auth/google/callback
 * OAuth 2.0 + PKCE callback from Google.
 *
 * Security:
 * - State is verified + consumed atomically (prevents CSRF replay)
 * - PKCE verifier is retrieved from stored state + sent to Google (prevents
 *   authorization-code injection — RFC 9700 §4.5)
 * - Both tokens are set as httpOnly cookies — NOT in the URL or fragment.
 *   URL fragments leak via browser history, JS access, and referrer headers.
 */
export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl
  const code = searchParams.get('code')
  const state = searchParams.get('state')
  const error = searchParams.get('error')

  const baseUrl =
    process.env.NEXT_PUBLIC_BASE_URL ?? 'http://localhost:3000'

  if (error) {
    return Response.redirect(
      `${baseUrl}/login?error=${encodeURIComponent(error)}`,
    )
  }

  if (!code || !state) {
    return Response.redirect(`${baseUrl}/login?error=missing_params`)
  }

  const redirectUri =
    process.env.GOOGLE_REDIRECT_URI ??
    `${baseUrl}/api/auth/google/callback`

  const { googleOAuthUseCase } = getContainer()
  const result = await googleOAuthUseCase.execute(
    { code, state, redirectUri },
    {
      ipAddress: getClientIp(req) ?? undefined,
      userAgent: getUserAgent(req) ?? undefined,
    },
  )

  if (result.isErr()) {
    const encoded = encodeURIComponent(result.error.message)
    return Response.redirect(`${baseUrl}/login?error=${encoded}`)
  }

  const oauthResult = result.value

  if (oauthResult.type === 'link_required') {
    return Response.redirect(
      `${baseUrl}/link-account?email=${encodeURIComponent(oauthResult.email)}`,
    )
  }

  const { accessToken, refreshToken } = oauthResult

  const rtExpiryDays = Number(process.env.REFRESH_TOKEN_EXPIRY_DAYS ?? 30)
  const atExpirySeconds = Number(process.env.ACCESS_TOKEN_EXPIRY_SECONDS ?? 900)

  const rtExpiry = new Date(Date.now() + rtExpiryDays * 86_400_000)
  const atExpiry = new Date(Date.now() + atExpirySeconds * 1000)

  // Set both tokens as httpOnly cookies — tokens never touch the URL
  let response = Response.redirect(`${baseUrl}/dashboard`, 302)
  response = setRefreshTokenCookie(response, refreshToken, rtExpiry)
  response = setAccessTokenCookie(response, accessToken, atExpiry)
  return response
}
