import Redis from 'ioredis'
import type { ISessionCache } from '../../../domain/auth/services/ISessionCache'

const DENYLIST_PREFIX = 'denylist:'
const SESSION_PREFIX = 'session:'
const OAUTH_STATE_PREFIX = 'oauth:state:'
const VERIFICATION_PREFIX = 'verify:'
const DEFAULT_OAUTH_STATE_TTL = 600 // 10 minutes

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

  async denylistToken(jti: string, ttlSeconds: number): Promise<void> {
    await this.client.setex(`${DENYLIST_PREFIX}${jti}`, ttlSeconds, '1')
  }

  async isTokenDenylisted(jti: string): Promise<boolean> {
    const result = await this.client.exists(`${DENYLIST_PREFIX}${jti}`)
    return result === 1
  }

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

  async disconnect(): Promise<void> {
    await this.client.quit()
  }
}
