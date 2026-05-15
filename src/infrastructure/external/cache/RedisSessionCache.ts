import Redis from 'ioredis'
import type { ISessionCache } from '@/domain/auth/services/ISessionCache'

const DENYLIST_PREFIX = 'denylist:'
const SESSION_PREFIX = 'session:'
const REVOKED_SESSION_PREFIX = 'revoked_session:'
const MIN_TOKEN_VERSION_PREFIX = 'user:minver:'
const OAUTH_STATE_PREFIX = 'oauth:state:'
const VERIFICATION_PREFIX = 'verify:'
const RATE_LIMIT_PREFIX = 'ratelimit:'
const DEFAULT_OAUTH_STATE_TTL = 600 // 10 minutes

/**
 * Atomic rate-limit Lua script.
 *
 * Increments the counter, sets TTL only on first increment (avoids
 * overwriting the window when requests arrive mid-window), then returns
 * [count, remaining_ttl].  Fully atomic — no TOCTOU race.
 */
const RATE_LIMIT_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {current, ttl}
`

/**
 * Redis-backed session cache.
 * Key naming convention: prefix:identifier
 * All keys have TTLs set to prevent unbounded memory growth.
 */
export class RedisSessionCache implements ISessionCache {
  private readonly client: Redis

  constructor(redisUrl: string) {
    this.client = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      enableOfflineQueue: false,
      lazyConnect: true,
    })

    this.client.on('error', (err) => {
      // Log but don't crash — degrade gracefully
      console.error('[RedisSessionCache] Redis error:', err.message)
    })
  }

  // ---------------------------------------------------------------------------
  // Access token denylist
  // ---------------------------------------------------------------------------

  async denylistToken(jti: string, ttlSeconds: number): Promise<void> {
    await this.client.setex(`${DENYLIST_PREFIX}${jti}`, ttlSeconds, '1')
  }

  async isTokenDenylisted(jti: string): Promise<boolean> {
    try {
      const result = await this.client.exists(`${DENYLIST_PREFIX}${jti}`)
      return result === 1
    } catch {
      return false // fail open: assume valid when Redis is unavailable
    }
  }

  // ---------------------------------------------------------------------------
  // Per-session revocation (rotation family)
  // ---------------------------------------------------------------------------

  async revokeSession(familyId: string, ttlSeconds: number): Promise<void> {
    await this.client.setex(
      `${REVOKED_SESSION_PREFIX}${familyId}`,
      ttlSeconds,
      '1',
    )
  }

  async isSessionRevoked(familyId: string): Promise<boolean> {
    try {
      const result = await this.client.exists(
        `${REVOKED_SESSION_PREFIX}${familyId}`,
      )
      return result === 1
    } catch {
      return false // fail open: assume valid when Redis is unavailable
    }
  }

  // ---------------------------------------------------------------------------
  // User-level token version (covers <15 min window post logout-all)
  // ---------------------------------------------------------------------------

  async setMinTokenVersion(
    userId: string,
    version: number,
    ttlSeconds: number,
  ): Promise<void> {
    await this.client.setex(
      `${MIN_TOKEN_VERSION_PREFIX}${userId}`,
      ttlSeconds,
      String(version),
    )
  }

  async getMinTokenVersion(userId: string): Promise<number | null> {
    const raw = await this.client.get(`${MIN_TOKEN_VERSION_PREFIX}${userId}`)
    if (raw === null) return null
    return parseInt(raw, 10)
  }

  // ---------------------------------------------------------------------------
  // Atomic rate limiting
  // ---------------------------------------------------------------------------

  async incrementRateLimit(
    key: string,
    windowSeconds: number,
    limit: number,
  ): Promise<{ count: number; isAllowed: boolean; resetAt: Date }> {
    const redisKey = `${RATE_LIMIT_PREFIX}${key}`
    const result = (await this.client.eval(
      RATE_LIMIT_SCRIPT,
      1,
      redisKey,
      String(windowSeconds),
    )) as [number, number]

    const count = result[0]
    const ttlRemaining = result[1] > 0 ? result[1] : windowSeconds
    const resetAt = new Date(Date.now() + ttlRemaining * 1000)

    return { count, isAllowed: count <= limit, resetAt }
  }

  // ---------------------------------------------------------------------------
  // Session metadata cache
  // ---------------------------------------------------------------------------

  async setSession(
    userId: string,
    jti: string,
    data: Record<string, string | number>,
    ttlSeconds: number,
  ): Promise<void> {
    const key = `${SESSION_PREFIX}${userId}:${jti}`
    await this.client.hset(key, data)
    await this.client.expire(key, ttlSeconds)
  }

  async clearUserSessions(userId: string): Promise<void> {
    const pattern = `${SESSION_PREFIX}${userId}:*`
    let cursor = '0'
    do {
      const [nextCursor, keys] = await this.client.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        100,
      )
      cursor = nextCursor
      if (keys.length > 0) {
        await this.client.del(...keys)
      }
    } while (cursor !== '0')
  }

  // ---------------------------------------------------------------------------
  // OAuth state (CSRF + PKCE verifier stored as JSON)
  // ---------------------------------------------------------------------------

  async setOAuthState(
    state: string,
    data: string,
    ttlSeconds = DEFAULT_OAUTH_STATE_TTL,
  ): Promise<void> {
    await this.client.setex(
      `${OAUTH_STATE_PREFIX}${state}`,
      ttlSeconds,
      data,
    )
  }

  async consumeOAuthState(state: string): Promise<string | null> {
    const key = `${OAUTH_STATE_PREFIX}${state}`
    // Atomic get-and-delete to prevent state reuse
    const [value] = await this.client
      .pipeline()
      .get(key)
      .del(key)
      .exec() as [[null, string | null], [null, number]]
    return value[1]
  }

  // ---------------------------------------------------------------------------
  // Verification codes (email verify, password reset)
  // ---------------------------------------------------------------------------

  async setVerificationCode(
    key: string,
    value: string,
    ttlSeconds: number,
  ): Promise<void> {
    await this.client.setex(`${VERIFICATION_PREFIX}${key}`, ttlSeconds, value)
  }

  async getVerificationCode(key: string): Promise<string | null> {
    return this.client.get(`${VERIFICATION_PREFIX}${key}`)
  }

  async deleteVerificationCode(key: string): Promise<void> {
    await this.client.del(`${VERIFICATION_PREFIX}${key}`)
  }

  // ---------------------------------------------------------------------------
  // Raw key lookup (PolicyInformationPoint, etc.)
  // ---------------------------------------------------------------------------

  async redisGet(key: string): Promise<string | null> {
    return this.client.get(key)
  }

  async disconnect(): Promise<void> {
    await this.client.quit()
  }
}
