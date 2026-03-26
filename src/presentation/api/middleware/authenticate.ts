import type { NextRequest } from 'next/server'
import { getContainer } from '@/infrastructure/container'
import type { AccessTokenClaims } from '@/domain/auth/services/ITokenGenerationService'
import { DomainError } from '@/domain/shared/Result'

export interface AuthContext {
  userId: string
  tokenVersion: number
  jti: string
  exp: number
  scope: string
}

/**
 * Extract and validate the access token from the request.
 * Checks:
 * 1. Extract from Authorization: Bearer OR httpOnly cookie
 * 2. Verify JWT signature (RS256)
 * 3. Check Redis denylist (fast path — catches logout/single-session revocation)
 * 4. Token version check is done via the JWT claim (ver) vs user DB on sensitive ops
 *
 * Returns null for optional auth routes — throws DomainError for required auth.
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
    // Fall back to httpOnly cookie
    rawToken = req.cookies.get('access_token')?.value ?? null
  }

  if (!rawToken) return null

  // 2. Verify JWT
  let claims: AccessTokenClaims
  try {
    claims = await tokenService.verifyAccessToken(rawToken)
  } catch {
    return null
  }

  // 3. Redis denylist check (fast path for revoked tokens)
  const isDenylisted = await sessionCache.isTokenDenylisted(claims.jti)
  if (isDenylisted) return null

  return {
    userId: claims.uid,
    tokenVersion: claims.ver,
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
