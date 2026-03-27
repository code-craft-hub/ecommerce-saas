/**
 * Port for Redis-backed session cache.
 * Used for fast token denylist lookups, session tracking, and rate limiting.
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
   * Mark an entire rotation family (session) as revoked.
   * TTL should match the maximum access token lifetime (e.g. 900s).
   * Used by RevokeSessionUseCase to invalidate in-flight access tokens.
   */
  revokeSession(familyId: string, ttlSeconds: number): Promise<void>

  /** Check if a rotation family has been explicitly revoked */
  isSessionRevoked(familyId: string): Promise<boolean>

  /**
   * Record the minimum valid token version for a user.
   * Called when tokenVersion is incremented (logout-all, password change).
   * TTL should match the maximum access token lifetime so the entry
   * auto-expires once all previously issued tokens have naturally expired.
   */
  setMinTokenVersion(
    userId: string,
    version: number,
    ttlSeconds: number,
  ): Promise<void>

  /**
   * Retrieve the minimum valid token version for a user.
   * Returns null if no entry exists (no recent version bump).
   */
  getMinTokenVersion(userId: string): Promise<number | null>

  /**
   * Atomically increment a rate-limit counter and return the result.
   * Uses a Lua script to guarantee atomicity (no TOCTOU race).
   *
   * @param key      - Redis key (caller includes prefix + identifier)
   * @param windowSeconds - Sliding window size in seconds
   * @param limit    - Maximum allowed requests within the window
   * @returns count (new total), isAllowed, and resetAt timestamp
   */
  incrementRateLimit(
    key: string,
    windowSeconds: number,
    limit: number,
  ): Promise<{ count: number; isAllowed: boolean; resetAt: Date }>

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

  /** Store OAuth state parameter (CSRF + PKCE verifier) — TTL 10 minutes */
  setOAuthState(state: string, data: string, ttlSeconds?: number): Promise<void>

  /** Retrieve and delete OAuth state (atomic get-and-delete) */
  consumeOAuthState(state: string): Promise<string | null>

  /** Store email verification or password reset token — TTL varies */
  setVerificationCode(key: string, value: string, ttlSeconds: number): Promise<void>
  getVerificationCode(key: string): Promise<string | null>
  deleteVerificationCode(key: string): Promise<void>

  /**
   * Raw key lookup — used by PolicyInformationPoint for IP reputation
   * and other authz-related cache entries.
   */
  redisGet(key: string): Promise<string | null>
}
