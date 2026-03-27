import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import type { AccessTokenClaims } from '@/domain/auth/services/ITokenGenerationService'
import { DomainError } from '@/domain/shared/Result'

export interface AuthContext {
  userId: string
  tokenVersion: number
  /** Session ID — rotation family ID, for per-session revocation checks */
  sessionId: string
  jti: string
  exp: number
  scope: string
}

/**
 * Extract and validate the access token from the request.
 *
 * Checks (in order of cost — cheapest first):
 * 1. Extract from Authorization: Bearer OR httpOnly cookie
 * 2. Verify JWT signature (RS256) — rejects tampered/expired tokens
 * 3. Redis denylist check on JTI — catches explicit logout (single session)
 * 4. Redis per-session revocation check on `sid` — catches RevokeSessionUseCase
 * 5. Redis minimum token version check — catches logout-all / password-change
 *    within the access-token lifetime window (covers the gap between version
 *    bump and natural token expiry)
 *
 * Steps 3-5 are all O(1) Redis GETs — combined latency is typically <1 ms.
 *
 * Returns null for optional-auth routes; throws DomainError for required auth.
 */
export async function extractAuthContext(
  req: NextRequest,
): Promise<AuthContext | null> {
  const { tokenService, sessionCache } = getContainer()

  // 1. Extract token
  let rawToken: string | null = null

  const authHeader = req.headers.get('authorization')
  if (authHeader?.startsWith('Bearer ')) {
    rawToken = authHeader.slice(7)
  } else {
    rawToken = req.cookies.get('access_token')?.value ?? null
  }

  if (!rawToken) return null

  // 2. Verify JWT signature + expiry
  let claims: AccessTokenClaims
  try {
    claims = await tokenService.verifyAccessToken(rawToken)
  } catch {
    return null
  }

  // 3. JTI denylist — fast path for explicitly logged-out tokens
  const isDenylisted = await sessionCache.isTokenDenylisted(claims.jti)
  if (isDenylisted) return null

  // 4. Per-session revocation — catches RevokeSessionUseCase
  //    sid is the rotationFamilyId embedded at token issuance.
  //    Tokens from before `sid` was added won't have this claim; those
  //    sessions fall back to natural expiry (acceptable 15-min window).
  if (claims.sid) {
    const isSessionRevoked = await sessionCache.isSessionRevoked(claims.sid)
    if (isSessionRevoked) return null
  }

  // 5. Token version check — catches logout-all / password-change
  //    Only performs the check when a minVersion entry exists in Redis
  //    (i.e. a version bump happened within the access-token lifetime window).
  const minVersion = await sessionCache.getMinTokenVersion(claims.uid)
  if (minVersion !== null && claims.ver < minVersion) {
    return null
  }

  return {
    userId: claims.uid,
    tokenVersion: claims.ver,
    sessionId: claims.sid ?? '',
    jti: claims.jti,
    exp: claims.exp,
    scope: claims.scope,
  }
}

/**
 * Require authentication — return 401 response if not authenticated.
 * Use in protected route handlers.
 */
export async function requireAuth(
  req: NextRequest,
): Promise<{ ctx: AuthContext } | { response: Response }> {
  const ctx = await extractAuthContext(req)
  if (!ctx) {
    return {
      response: Response.json(
        { error: 'Unauthorized', code: 'UNAUTHORIZED' },
        { status: 401 },
      ),
    }
  }
  return { ctx }
}

/**
 * Helper: extract client IP from Next.js request.
 */
export function getClientIp(req: NextRequest): string | null {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    req.headers.get('x-real-ip') ??
    null
  )
}

/**
 * Helper: get user agent string.
 */
export function getUserAgent(req: NextRequest): string | null {
  return req.headers.get('user-agent')
}
