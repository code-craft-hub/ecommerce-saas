import { describe, it, expect } from 'vitest'
import {
  PlaintextPassword,
  HashedPassword,
} from '@/domain/auth/value-objects/Password'

describe('PlaintextPassword Value Object', () => {
  const validPassword = 'SecureP@ssw0rd!123'

  describe('create()', () => {
    it('creates a valid password', () => {
      const result = PlaintextPassword.create(validPassword)
      expect(result.isOk()).toBe(true)
    })

    it('exposes value for hashing only', () => {
      const result = PlaintextPassword.create(validPassword)
      expect(result.isOk() && result.value.value).toBe(validPassword)
    })

    it('rejects password under 12 chars', () => {
      const result = PlaintextPassword.create('Short!1A')
      expect(result.isErr()).toBe(true)
      expect(result.isErr() && result.error.code).toBe('WEAK_PASSWORD')
    })

    it('rejects password over 128 chars', () => {
      const long = 'A1!a' + 'x'.repeat(200)
      const result = PlaintextPassword.create(long)
      expect(result.isErr()).toBe(true)
    })

    it('rejects password without uppercase', () => {
      const result = PlaintextPassword.create('lowercase123!!!')
      expect(result.isErr()).toBe(true)
    })

    it('rejects password without lowercase', () => {
      const result = PlaintextPassword.create('UPPERCASE123!!!')
      expect(result.isErr()).toBe(true)
    })

    it('rejects password without digit', () => {
      const result = PlaintextPassword.create('NoDigits!!!!ABCDE')
      expect(result.isErr()).toBe(true)
    })

    it('rejects password without special character', () => {
      const result = PlaintextPassword.create('NoSpecial1234567A')
      expect(result.isErr()).toBe(true)
    })

    it('rejects password with leading whitespace', () => {
      const result = PlaintextPassword.create(' Valid@123Password')
      expect(result.isErr()).toBe(true)
    })

    it('rejects password with trailing whitespace', () => {
      const result = PlaintextPassword.create('Valid@123Password ')
      expect(result.isErr()).toBe(true)
    })
  })

  describe('security', () => {
    it('toJSON returns REDACTED', () => {
      const result = PlaintextPassword.create(validPassword)
      expect(result.isOk() && result.value.toJSON()).toBe('[REDACTED]')
    })

    it('toString returns REDACTED', () => {
      const result = PlaintextPassword.create(validPassword)
      expect(result.isOk() && result.value.toString()).toBe('[REDACTED]')
    })

    it('JSON.stringify does not leak plaintext', () => {
      const result = PlaintextPassword.create(validPassword)
      if (result.isOk()) {
        const json = JSON.stringify({ pw: result.value })
        expect(json).not.toContain(validPassword)
      }
    })
  })
})

describe('HashedPassword Value Object', () => {
  it('creates from hash string', () => {
    const hash = '$argon2id$v=19$m=19456,t=2,p=1$abc$xyz'
    const pw = HashedPassword.fromHash(hash)
    expect(pw.hash).toBe(hash)
  })

  it('toJSON returns REDACTED', () => {
    const pw = HashedPassword.fromHash('somehash')
    expect(pw.toJSON()).toBe('[REDACTED]')
  })
})
