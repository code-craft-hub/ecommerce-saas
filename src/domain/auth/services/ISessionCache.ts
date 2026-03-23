/**
 * Port for Redis-backed session cache.
 * Used for fast token denylist lookups and session tracking.
 */
export interface ISessionCache {
  /**
   * Add a JTI to the denylist (token revocation).
   * TTL should match the token's remaining lifetime.
   */
  denylistToken(jti: string, ttlSeconds: number): Promise<void>

  /** Check if a JTI is in the denylist */
  isTokenDenylisted(jti: string): Promise<boolean>

  /**
   * Cache active session metadata.
   * Key: session:{userId}:{jti}
   */
  setSession(
    userId: string,
    jti: string,
    data: Record<string, string | number>,
    ttlSeconds: number,
  ): Promise<void>

  /** Invalidate all session cache entries for a user */
  clearUserSessions(userId: string): Promise<void>

  /** Store OAuth state parameter (CSRF) — TTL 10 minutes */
  setOAuthState(state: string, data: string, ttlSeconds?: number): Promise<void>

  /** Retrieve and delete OAuth state */
  consumeOAuthState(state: string): Promise<string | null>

  /** Store email verification or password reset token — TTL varies */
  setVerificationCode(key: string, value: string, ttlSeconds: number): Promise<void>
  getVerificationCode(key: string): Promise<string | null>
  deleteVerificationCode(key: string): Promise<void>
}
