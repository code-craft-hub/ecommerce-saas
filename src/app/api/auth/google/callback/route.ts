import type { NextRequest } from 'next/server'
import { getContainer } from '../../../../../infrastructure/container'
import {
  errorResponse,
  setRefreshTokenCookie,
} from '../../../../../presentation/api/middleware/response'
import {
  getClientIp,
  getUserAgent,
} from '../../../../../presentation/api/middleware/authenticate'

/**
 * GET /api/auth/google/callback
 * OAuth 2.0 callback from Google.
 * Handles: new users, existing users, account linking suggestions.
 */
export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl
  const code = searchParams.get('code')
  const state = searchParams.get('state')
  const error = searchParams.get('error')

  const baseUrl =
    process.env.NEXT_PUBLIC_BASE_URL ?? 'http://localhost:3000'

  // Google returned an error (user denied consent, etc.)
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
    // Redirect to link page — user needs to authenticate existing account
    return Response.redirect(
      `${baseUrl}/link-account?email=${encodeURIComponent(oauthResult.email)}`,
    )
  }

  // Authenticated — set cookie and redirect to dashboard
  const { accessToken, refreshToken } = oauthResult

  // We need to redirect browser but also set the cookie and token
  // Strategy: redirect to a page that picks up the access token from the URL
  // For security, we use a short-lived state token approach
  // Better: set cookie first, then redirect
  const rtExpiry = new Date(
    Date.now() +
      Number(process.env.REFRESH_TOKEN_EXPIRY_DAYS ?? 30) * 86_400_000,
  )

  // Build redirect with access token in URL fragment (not query string — not logged by server)
  // The fragment is never sent to the server, so it's safe
  const redirectResponse = Response.redirect(
    `${baseUrl}/dashboard#at=${encodeURIComponent(accessToken)}`,
    302,
  )
  return setRefreshTokenCookie(redirectResponse, refreshToken, rtExpiry)
}
