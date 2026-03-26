import { describe, it, expect } from 'vitest'
import { ok, err, Ok, Err, DomainError } from '@/domain/shared/Result'

describe('Result monad', () => {
  describe('Ok', () => {
    it('isOk() returns true', () => {
      expect(ok(42).isOk()).toBe(true)
    })
    it('isErr() returns false', () => {
      expect(ok(42).isErr()).toBe(false)
    })
    it('map() transforms value', () => {
      const result = ok(2).map((x) => x * 3)
      expect(result.isOk() && result.value).toBe(6)
    })
    it('flatMap() chains results', () => {
      const result = ok(2).flatMap((x) => ok(x * 3))
      expect(result.isOk() && result.value).toBe(6)
    })
    it('flatMap() short-circuits on error', () => {
      const error = new DomainError('INTERNAL_ERROR', 'fail')
      const result = ok(2).flatMap(() => err(error))
      expect(result.isErr()).toBe(true)
    })
    it('getOrElse() returns value', () => {
      expect(ok(42).getOrElse(0)).toBe(42)
    })
  })

  describe('Err', () => {
    const error = new DomainError('INTERNAL_ERROR', 'oops')

    it('isErr() returns true', () => {
      expect(err(error).isErr()).toBe(true)
    })
    it('isOk() returns false', () => {
      expect(err(error).isOk()).toBe(false)
    })
    it('map() is a no-op', () => {
      const result = err(error).map(() => 'transformed')
      expect(result.isErr()).toBe(true)
    })
    it('flatMap() is a no-op', () => {
      const result = err(error).flatMap(() => ok('value'))
      expect(result.isErr()).toBe(true)
    })
    it('getOrElse() returns default', () => {
      expect(err(error).getOrElse(99)).toBe(99)
    })
  })
})

describe('DomainError', () => {
  it('invalidCredentials() has correct code', () => {
    const e = DomainError.invalidCredentials()
    expect(e.code).toBe('INVALID_CREDENTIALS')
  })

  it('weakPassword() has correct code', () => {
    const e = DomainError.weakPassword()
    expect(e.code).toBe('WEAK_PASSWORD')
  })

  it('userAlreadyExists() includes email in message', () => {
    const e = DomainError.userAlreadyExists('test@example.com')
    expect(e.message).toContain('test@example.com')
  })

  it('refreshTokenReuseDetected() has high severity implication', () => {
    const e = DomainError.refreshTokenReuseDetected()
    expect(e.code).toBe('REFRESH_TOKEN_REUSE_DETECTED')
  })

  it('is instanceof Error', () => {
    const e = DomainError.unauthorized()
    expect(e).toBeInstanceOf(Error)
  })
})
