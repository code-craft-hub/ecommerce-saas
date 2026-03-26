import { describe, it, expect } from 'vitest'
import {
  hashToken,
  generateOpaqueToken,
  timingSafeEqual,
} from '@/infrastructure/services/tokenUtils'

describe('tokenUtils', () => {
  describe('hashToken()', () => {
    it('produces 64-char hex string (SHA-256)', async () => {
      const hash = await hashToken('my-secret-token')
      expect(hash).toHaveLength(64)
      expect(hash).toMatch(/^[0-9a-f]+$/)
    })

    it('same input → same output (deterministic)', async () => {
      const token = 'consistent-token'
      const h1 = await hashToken(token)
      const h2 = await hashToken(token)
      expect(h1).toBe(h2)
    })

    it('different inputs → different outputs', async () => {
      const h1 = await hashToken('token-a')
      const h2 = await hashToken('token-b')
      expect(h1).not.toBe(h2)
    })

    it('matches known SHA-256 value', async () => {
      // echo -n "test" | sha256sum
      const hash = await hashToken('test')
      expect(hash).toBe(
        '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      )
    })
  })

  describe('generateOpaqueToken()', () => {
    it('generates 64-char hex string', () => {
      const token = generateOpaqueToken()
      expect(token).toHaveLength(64)
      expect(token).toMatch(/^[0-9a-f]+$/)
    })

    it('generates unique tokens', () => {
      const t1 = generateOpaqueToken()
      const t2 = generateOpaqueToken()
      expect(t1).not.toBe(t2)
    })
  })

  describe('timingSafeEqual()', () => {
    it('returns true for identical strings', () => {
      expect(timingSafeEqual('abc', 'abc')).toBe(true)
    })

    it('returns false for different strings of same length', () => {
      expect(timingSafeEqual('abc', 'abd')).toBe(false)
    })

    it('returns false for different-length strings', () => {
      expect(timingSafeEqual('abc', 'abcd')).toBe(false)
    })

    it('returns false for empty vs non-empty', () => {
      expect(timingSafeEqual('', 'abc')).toBe(false)
    })

    it('returns true for empty vs empty', () => {
      expect(timingSafeEqual('', '')).toBe(true)
    })
  })
})
