import type { TokenPair } from '@/domain/auth/value-objects/TokenPair'

export interface AccessTokenClaims {
  /** Subject — user ID */
  sub: string
  /** Audience — e.g. 'myapp' */
  aud: string
  /** Issuer — e.g. 'https://myapp.com' */
  iss: string
  /** JWT ID — for denylist revocation */
  jti: string
  /** Issued at (epoch seconds) */
  iat: number
  /** Expiration (epoch seconds) */
  exp: number
  /** User ID (duplicate of sub for clarity) */
  uid: string
  /** Token version (matches user.token_version for all-session invalidation) */
  ver: number
  /**
   * Session ID — the rotation family ID that ties this access token to a
   * specific login session.  Used by authenticate middleware to detect
   * per-session revocation without a DB lookup.
   */
  sid: string
  /** Scopes granted */
  scope: string
}

export interface ITokenGenerationService {
  generateTokenPair(params: {
    userId: string
    tokenVersion: number
    /** Rotation family ID — becomes the `sid` claim in the access token */
    rotationFamilyId: string
    deviceId?: string | null
  }): Promise<TokenPair>

  /** Verify and decode an access token — throws on failure */
  verifyAccessToken(token: string): Promise<AccessTokenClaims>

  /** Generate a short-lived signed token for email verification / password reset */
  generateVerificationToken(payload: {
    userId: string
    email: string
    purpose: 'email_verification' | 'password_reset'
  }): Promise<string>

  verifyVerificationToken(token: string): Promise<{
    userId: string
    email: string
    purpose: 'email_verification' | 'password_reset'
  }>
}
