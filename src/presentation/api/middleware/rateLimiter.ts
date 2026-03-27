import { getContainer } from '@/infrastructure/container'

/**
 * Token-bucket rate limiter backed by Redis.
 *
 * All counters are incremented atomically via a Lua script — no TOCTOU race.
 *
 * Policies (per RFC 9700 §2.2 + OWASP guidance):
 * - login:           5 attempts  / 60 s   per IP+email
 * - signup:         10 requests  / 60 s   per IP
 * - password_reset:  3 requests  / 3600 s per email
 * - refresh:        30 requests  / 60 s   per userId
 * - oauth:          10 requests  / 60 s   per IP
 * - verify_email:   10 requests  / 3600 s per email
 */

interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetAt: Date
}

const POLICIES = {
  login:          { limit: 5,  windowSeconds: 60   },
  signup:         { limit: 10, windowSeconds: 60   },
  password_reset: { limit: 3,  windowSeconds: 3600 },
  refresh:        { limit: 30, windowSeconds: 60   },
  oauth:          { limit: 10, windowSeconds: 60   },
  verify_email:   { limit: 10, windowSeconds: 3600 },
} as const

type RateLimitPolicy = keyof typeof POLICIES

export async function checkRateLimit(
  policy: RateLimitPolicy,
  identifier: string,
): Promise<RateLimitResult> {
  const { sessionCache } = getContainer()
  const { limit, windowSeconds } = POLICIES[policy]

  const key = `${policy}:${identifier}`
  const { count, isAllowed, resetAt } = await sessionCache.incrementRateLimit(
    key,
    windowSeconds,
    limit,
  )

  return {
    allowed: isAllowed,
    remaining: Math.max(0, limit - count),
    resetAt,
  }
}

export function rateLimitResponse(resetAt: Date): Response {
  return Response.json(
    { error: 'Too many requests', code: 'RATE_LIMIT_EXCEEDED' },
    {
      status: 429,
      headers: {
        'Retry-After': String(Math.ceil((resetAt.getTime() - Date.now()) / 1000)),
        'X-RateLimit-Reset': String(resetAt.getTime()),
      },
    },
  )
}
