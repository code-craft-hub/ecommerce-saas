import { DomainError, type Result, err, ok } from '@/domain/shared/Result'

/**
 * Password Value Object — OWASP-compliant strength validation.
 * Stores the raw plaintext transiently for hashing; NEVER persists plaintext.
 *
 * Password policy (OWASP 2021):
 *  - Minimum 12 characters
 *  - At least one uppercase letter
 *  - At least one lowercase letter
 *  - At least one digit
 *  - At least one special character
 *  - No leading/trailing whitespace
 *  - Maximum 128 characters (prevent DoS via huge bcrypt/argon2 inputs)
 */
export class PlaintextPassword {
  private static readonly MIN_LENGTH = 12
  private static readonly MAX_LENGTH = 128

  private constructor(private readonly _value: string) {}

  static create(raw: string): Result<PlaintextPassword> {
    if (raw.length < PlaintextPassword.MIN_LENGTH) {
      return err(DomainError.weakPassword())
    }
    if (raw.length > PlaintextPassword.MAX_LENGTH) {
      return err(DomainError.weakPassword())
    }
    if (raw !== raw.trim()) {
      return err(DomainError.weakPassword())
    }
    if (!/[A-Z]/.test(raw)) return err(DomainError.weakPassword())
    if (!/[a-z]/.test(raw)) return err(DomainError.weakPassword())
    if (!/[0-9]/.test(raw)) return err(DomainError.weakPassword())
    if (!/[^A-Za-z0-9]/.test(raw)) return err(DomainError.weakPassword())

    return ok(new PlaintextPassword(raw))
  }

  /** Only expose value to hashing service — never log or serialize */
  get value(): string {
    return this._value
  }

  /** Prevent accidental serialization */
  toJSON(): string {
    return '[REDACTED]'
  }

  toString(): string {
    return '[REDACTED]'
  }
}

/**
 * HashedPassword — stores Argon2id hash.
 * Created only by PasswordHashingService.
 */
export class HashedPassword {
  private constructor(private readonly _hash: string) {}

  static fromHash(hash: string): HashedPassword {
    return new HashedPassword(hash)
  }

  get hash(): string {
    return this._hash
  }

  toJSON(): string {
    return '[REDACTED]'
  }
  toString(): string {
    return '[REDACTED]'
  }
}
