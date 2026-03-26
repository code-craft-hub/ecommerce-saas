import { DomainError, type DomainErrorCode } from '@/domain/shared/Result'

/**
 * Maps DomainErrorCode to HTTP status codes.
 * Never expose internal details — return sanitized error responses.
 */
const ERROR_STATUS_MAP: Record<DomainErrorCode, number> = {
  INVALID_EMAIL: 422,
  INVALID_PASSWORD: 422,
  WEAK_PASSWORD: 422,
  USER_NOT_FOUND: 404,
  USER_ALREADY_EXISTS: 409,
  EMAIL_NOT_VERIFIED: 403,
  INVALID_CREDENTIALS: 401,
  INVALID_TOKEN: 401,
  TOKEN_EXPIRED: 401,
  TOKEN_REVOKED: 401,
  SESSION_NOT_FOUND: 404,
  REFRESH_TOKEN_REUSE_DETECTED: 401,
  OAUTH_ACCOUNT_NOT_FOUND: 404,
  OAUTH_ACCOUNT_ALREADY_LINKED: 409,
  OAUTH_PROVIDER_ERROR: 502,
  PASSWORD_ALREADY_SET: 409,
  PASSWORD_NOT_SET: 400,
  ACCOUNT_LOCKED: 423,
  RATE_LIMIT_EXCEEDED: 429,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  INTERNAL_ERROR: 500,
  CSRF_VALIDATION_FAILED: 403,
  PERMISSION_DENIED: 403,
  ROLE_NOT_FOUND: 404,
  ROLE_ALREADY_ASSIGNED: 409,
  POLICY_VIOLATION: 403,
}

export function errorResponse(error: DomainError): Response {
  const status = ERROR_STATUS_MAP[error.code] ?? 500
  return Response.json(
    {
      error: error.message,
      code: error.code,
    },
    { status },
  )
}

export function successResponse<T>(data: T, status = 200): Response {
  return Response.json(data, { status })
}

/**
 * Set httpOnly refresh token cookie.
 * SameSite=Strict prevents CSRF. Secure in production.
 */
export function setRefreshTokenCookie(
  response: Response,
  refreshToken: string,
  expiresAt: Date,
): Response {
  const isProduction = process.env.NODE_ENV === 'production'
  const cookieValue = [
    `refresh_token=${refreshToken}`,
    `HttpOnly`,
    isProduction ? `Secure` : '',
    `SameSite=Strict`,
    `Path=/api/auth`,
    `Expires=${expiresAt.toUTCString()}`,
  ]
    .filter(Boolean)
    .join('; ')

  const headers = new Headers(response.headers)
  headers.set('Set-Cookie', cookieValue)

  return new Response(response.body, {
    status: response.status,
    headers,
  })
}

export function clearRefreshTokenCookie(): string {
  return [
    'refresh_token=',
    'HttpOnly',
    'SameSite=Strict',
    'Path=/api/auth',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    process.env.NODE_ENV === 'production' ? 'Secure' : '',
  ]
    .filter(Boolean)
    .join('; ')
}
