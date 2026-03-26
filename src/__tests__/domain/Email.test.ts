import { describe, it, expect } from 'vitest'
import { Email } from '@/domain/auth/value-objects/Email'

describe('Email Value Object', () => {
  describe('create()', () => {
    it('creates a valid email', () => {
      const result = Email.create('user@example.com')
      expect(result.isOk()).toBe(true)
      expect(result.isOk() && result.value.value).toBe('user@example.com')
    })

    it('normalizes to lowercase', () => {
      const result = Email.create('User@Example.COM')
      expect(result.isOk() && result.value.value).toBe('user@example.com')
    })

    it('trims whitespace', () => {
      const result = Email.create('  user@example.com  ')
      expect(result.isOk() && result.value.value).toBe('user@example.com')
    })

    it('rejects empty string', () => {
      const result = Email.create('')
      expect(result.isErr()).toBe(true)
    })

    it('rejects missing @', () => {
      const result = Email.create('notanemail')
      expect(result.isErr()).toBe(true)
    })

    it('rejects missing TLD', () => {
      const result = Email.create('user@localhost')
      expect(result.isErr()).toBe(true)
    })

    it('rejects email over 254 chars', () => {
      const longEmail = 'a'.repeat(250) + '@b.com'
      const result = Email.create(longEmail)
      expect(result.isErr()).toBe(true)
    })

    it('accepts plus-aliased emails', () => {
      const result = Email.create('user+tag@example.com')
      expect(result.isOk()).toBe(true)
    })

    it('accepts subdomains', () => {
      const result = Email.create('user@mail.example.co.uk')
      expect(result.isOk()).toBe(true)
    })
  })

  describe('equals()', () => {
    it('equal emails are equal', () => {
      const a = Email.create('user@example.com')
      const b = Email.create('user@example.com')
      expect(a.isOk() && b.isOk() && a.value.equals(b.value)).toBe(true)
    })

    it('different emails are not equal', () => {
      const a = Email.create('a@example.com')
      const b = Email.create('b@example.com')
      expect(a.isOk() && b.isOk() && a.value.equals(b.value)).toBe(false)
    })

    it('case-insensitive equality', () => {
      const a = Email.create('User@Example.com')
      const b = Email.create('user@example.com')
      expect(a.isOk() && b.isOk() && a.value.equals(b.value)).toBe(true)
    })
  })
})
