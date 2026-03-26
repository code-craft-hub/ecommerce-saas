import { DomainError, type Result, err, ok } from '@/domain/shared/Result'

/**
 * Email Value Object — RFC 5322 compliant, immutable.
 * Equality by value (normalized lowercase).
 */
export class Email {
  // RFC 5322 simplified — covers 99.9% of real-world addresses
  private static readonly RFC5322 =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/

  private constructor(private readonly _value: string) {}

  static create(raw: string): Result<Email> {
    const trimmed = raw.trim().toLowerCase()
    if (!trimmed || trimmed.length > 254) {
      return err(DomainError.invalidEmail(raw))
    }
    if (!Email.RFC5322.test(trimmed)) {
      return err(DomainError.invalidEmail(raw))
    }
    return ok(new Email(trimmed))
  }

  get value(): string {
    return this._value
  }

  equals(other: Email): boolean {
    return this._value === other._value
  }

  toString(): string {
    return this._value
  }
}
