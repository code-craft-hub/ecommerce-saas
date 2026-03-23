import { getContainer } from '../../../infrastructure/container'

/**
 * Token-bucket rate limiter backed by Redis.
 *
 * Policies:
 * - Login: 5 attempts / minute per IP+email combo
 * - Password reset: 3 requests / hour per email
 * - Signup: 10 requests / minute per IP
 * - Refresh: 30 requests / minute per userId
 */

interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetAt: Date
}

const POLICIES = {
  login: { limit: 5, windowSeconds: 60 },
  signup: { limit: 10, windowSeconds: 60 },
  password_reset: { limit: 3, windowSeconds: 3600 },
  refresh: { limit: 30, windowSeconds: 60 },
  oauth: { limit: 10, windowSeconds: 60 },
} as const

type RateLimitPolicy = keyof typeof POLICIES

export async function checkRateLimit(
  policy: RateLimitPolicy,
  identifier: string,
): Promise<RateLimitResult> {
  const { sessionCache } = getContainer()
  const { limit, windowSeconds } = POLICIES[policy]

  const key = `ratelimit:${policy}:${identifier}`
  const now = Date.now()
  const windowMs = windowSeconds * 1000
  const resetAt = new Date(Math.ceil(now / windowMs) * windowMs)

  // Retrieve current count
  const current = await sessionCache.getVerificationCode(key)
  const count = current ? parseInt(current, 10) : 0

  if (count >= limit) {
    return { allowed: false, remaining: 0, resetAt }
  }

  // Increment counter
  const newCount = count + 1
  const ttl = Math.ceil((resetAt.getTime() - now) / 1000)
  await sessionCache.setVerificationCode(key, String(newCount), ttl)

  return {
    allowed: true,
    remaining: limit - newCount,
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
