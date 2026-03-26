/**
 * Railway-oriented programming: Result<T, E> monad.
 * Eliminates exception-driven control flow in domain/application layers.
 */

export type Result<T, E = DomainError> = Ok<T> | Err<E>

export class Ok<T> {
  readonly _tag = 'Ok' as const
  constructor(readonly value: T) {}

  isOk(): this is Ok<T> {
    return true
  }
  isErr(): this is Err<never> {
    return false
  }
  map<U>(fn: (value: T) => U): Ok<U> {
    return new Ok(fn(this.value))
  }
  flatMap<U, F>(fn: (value: T) => Result<U, F>): Result<U, F> {
    return fn(this.value)
  }
  getOrElse(_default: T): T {
    return this.value
  }
}

export class Err<E> {
  readonly _tag = 'Err' as const
  constructor(readonly error: E) {}

  isOk(): this is Ok<never> {
    return false
  }
  isErr(): this is Err<E> {
    return true
  }
  map<U>(_fn: (value: never) => U): Err<E> {
    return this
  }
  flatMap<U, F>(_fn: (value: never) => Result<U, F>): Err<E> {
    return this
  }
  getOrElse<T>(defaultValue: T): T {
    return defaultValue
  }
}

export const ok = <T>(value: T): Ok<T> => new Ok(value)
export const err = <E>(error: E): Err<E> => new Err(error)

// ---------------------------------------------------------------------------
// Domain Error Hierarchy
// ---------------------------------------------------------------------------

export type DomainErrorCode =
  | 'INVALID_EMAIL'
  | 'INVALID_PASSWORD'
  | 'WEAK_PASSWORD'
  | 'USER_NOT_FOUND'
  | 'USER_ALREADY_EXISTS'
  | 'EMAIL_NOT_VERIFIED'
  | 'INVALID_CREDENTIALS'
  | 'INVALID_TOKEN'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_REVOKED'
  | 'SESSION_NOT_FOUND'
  | 'REFRESH_TOKEN_REUSE_DETECTED'
  | 'OAUTH_ACCOUNT_NOT_FOUND'
  | 'OAUTH_ACCOUNT_ALREADY_LINKED'
  | 'OAUTH_PROVIDER_ERROR'
  | 'PASSWORD_ALREADY_SET'
  | 'PASSWORD_NOT_SET'
  | 'ACCOUNT_LOCKED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'INTERNAL_ERROR'
  | 'CSRF_VALIDATION_FAILED'
  // Authorization framework
  | 'PERMISSION_DENIED'
  | 'ROLE_NOT_FOUND'
  | 'ROLE_ALREADY_ASSIGNED'
  | 'POLICY_VIOLATION'

export class DomainError extends Error {
  constructor(
    readonly code: DomainErrorCode,
    message: string,
    readonly metadata?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'DomainError'
    // Maintain proper prototype chain in transpiled environments
    Object.setPrototypeOf(this, new.target.prototype)
  }

  static invalidEmail(email: string): DomainError {
    return new DomainError('INVALID_EMAIL', `Invalid email address: ${email}`)
  }
  static weakPassword(): DomainError {
    return new DomainError(
      'WEAK_PASSWORD',
      'Password does not meet strength requirements',
    )
  }
  static invalidCredentials(): DomainError {
    return new DomainError('INVALID_CREDENTIALS', 'Invalid email or password')
  }
  static userNotFound(): DomainError {
    return new DomainError('USER_NOT_FOUND', 'User not found')
  }
  static userAlreadyExists(email: string): DomainError {
    return new DomainError(
      'USER_ALREADY_EXISTS',
      `User with email ${email} already exists`,
    )
  }
  static invalidToken(reason?: string): DomainError {
    return new DomainError(
      'INVALID_TOKEN',
      reason ? `Invalid token: ${reason}` : 'Invalid token',
    )
  }
  static tokenExpired(): DomainError {
    return new DomainError('TOKEN_EXPIRED', 'Token has expired')
  }
  static tokenRevoked(): DomainError {
    return new DomainError('TOKEN_REVOKED', 'Token has been revoked')
  }
  static refreshTokenReuseDetected(): DomainError {
    return new DomainError(
      'REFRESH_TOKEN_REUSE_DETECTED',
      'Refresh token reuse detected — possible token theft. All sessions invalidated.',
    )
  }
  static accountLocked(): DomainError {
    return new DomainError(
      'ACCOUNT_LOCKED',
      'Account temporarily locked due to too many failed attempts',
    )
  }
  static rateLimitExceeded(): DomainError {
    return new DomainError('RATE_LIMIT_EXCEEDED', 'Rate limit exceeded')
  }
  static unauthorized(): DomainError {
    return new DomainError('UNAUTHORIZED', 'Authentication required')
  }
  static forbidden(): DomainError {
    return new DomainError('FORBIDDEN', 'Access denied')
  }
  static internal(msg?: string): DomainError {
    return new DomainError('INTERNAL_ERROR', msg ?? 'Internal server error')
  }
  static passwordAlreadySet(): DomainError {
    return new DomainError(
      'PASSWORD_ALREADY_SET',
      'Password is already set for this account',
    )
  }
  static passwordNotSet(): DomainError {
    return new DomainError(
      'PASSWORD_NOT_SET',
      'No password set — use OAuth login',
    )
  }
  static oauthAccountAlreadyLinked(provider: string): DomainError {
    return new DomainError(
      'OAUTH_ACCOUNT_ALREADY_LINKED',
      `${provider} account is already linked to a user`,
    )
  }
  static emailNotVerified(): DomainError {
    return new DomainError(
      'EMAIL_NOT_VERIFIED',
      'Email address has not been verified',
    )
  }
  static csrfValidationFailed(): DomainError {
    return new DomainError('CSRF_VALIDATION_FAILED', 'CSRF validation failed')
  }
  static permissionDenied(action?: string, resource?: string): DomainError {
    const detail = action && resource ? ` (${action} on ${resource})` : ''
    return new DomainError('PERMISSION_DENIED', `Permission denied${detail}`)
  }
  static roleNotFound(role: string): DomainError {
    return new DomainError('ROLE_NOT_FOUND', `Role not found: ${role}`)
  }
  static roleAlreadyAssigned(role: string): DomainError {
    return new DomainError('ROLE_ALREADY_ASSIGNED', `Role already assigned: ${role}`)
  }
  static policyViolation(policy: string, reason: string): DomainError {
    return new DomainError('POLICY_VIOLATION', `Policy '${policy}' violated: ${reason}`)
  }
}
