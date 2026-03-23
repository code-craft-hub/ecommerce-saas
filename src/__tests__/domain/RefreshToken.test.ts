import { describe, it, expect, beforeEach, vi } from 'vitest'
import { RefreshToken } from '../../domain/auth/entities/RefreshToken'

function makeToken(overrides: Partial<{
  expiresAt: Date
  revokedAt: Date | null
  rotatedAt: Date | null
}> = {}): RefreshToken {
  return RefreshToken.create({
    id: crypto.randomUUID(),
    userId: 'user-1',
    tokenHash: 'abc123',
    rotationFamilyId: 'family-1',
    expiresAt: overrides.expiresAt ?? new Date(Date.now() + 86_400_000),
    deviceId: null,
    ipAddress: '127.0.0.1',
    userAgentHash: null,
  })
}

describe('RefreshToken entity', () => {
  describe('isValid', () => {
    it('is valid when not expired, revoked, or rotated', () => {
      const token = makeToken()
      expect(token.isValid).toBe(true)
    })

    it('is invalid when expired', () => {
      const token = makeToken({
        expiresAt: new Date(Date.now() - 1000),
      })
      expect(token.isValid).toBe(false)
    })
  })

  describe('rotate()', () => {
    it('sets rotatedAt', () => {
      const token = makeToken()
      expect(token.rotatedAt).toBeNull()
      token.rotate()
      expect(token.rotatedAt).toBeInstanceOf(Date)
    })

    it('marks token as invalid after rotation', () => {
      const token = makeToken()
      token.rotate()
      expect(token.isValid).toBe(false)
    })
  })

  describe('revoke()', () => {
    it('sets revokedAt', () => {
      const token = makeToken()
      expect(token.revokedAt).toBeNull()
      token.revoke()
      expect(token.revokedAt).toBeInstanceOf(Date)
    })

    it('marks token as invalid after revocation', () => {
      const token = makeToken()
      token.revoke()
      expect(token.isValid).toBe(false)
    })
  })

  describe('markUsed()', () => {
    it('sets usedAt timestamp', () => {
      const token = makeToken()
      expect(token.usedAt).toBeNull()
      token.markUsed()
      expect(token.usedAt).toBeInstanceOf(Date)
    })
  })

  describe('isExpired', () => {
    it('returns false for future expiry', () => {
      const token = makeToken({ expiresAt: new Date(Date.now() + 10_000) })
      expect(token.isExpired).toBe(false)
    })

    it('returns true for past expiry', () => {
      const token = makeToken({ expiresAt: new Date(Date.now() - 1) })
      expect(token.isExpired).toBe(true)
    })
  })
})
