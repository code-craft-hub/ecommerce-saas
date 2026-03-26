import { describe, it, expect, beforeEach } from 'vitest'
import { RefreshTokenUseCase } from '@/application/auth/refresh/RefreshTokenUseCase'
import { RefreshToken } from '@/domain/auth/entities/RefreshToken'
import { User } from '@/domain/auth/entities/User'
import { Email } from '@/domain/auth/value-objects/Email'
import { TokenPair } from '@/domain/auth/value-objects/TokenPair'
import { hashToken } from '@/infrastructure/services/tokenUtils'

// Re-use fakes from SignupUseCase test (simplified inline versions)
class FakeUserRepo {
  users = new Map<string, User>()
  async findById(id: string) { return this.users.get(id) ?? null }
  async findByEmail() { return null }
  async save(u: User) { this.users.set(u.id, u) }
  async update(u: User) { this.users.set(u.id, u) }
  async delete() {}
}

class FakeRTRepo {
  tokens = new Map<string, RefreshToken>()
  families: Set<string> = new Set()

  async findByHash(hash: string) {
    for (const t of this.tokens.values()) {
      if (t.tokenHash === hash) return t
    }
    return null
  }
  async findById(id: string) { return this.tokens.get(id) ?? null }
  async findActiveByUserId() { return [] }
  async save(t: RefreshToken) { this.tokens.set(t.id, t) }
  async update(t: RefreshToken) { this.tokens.set(t.id, t) }
  async revokeAllForUser() { return 0 }
  async revokeFamilyTokens(familyId: string) {
    this.families.add(familyId)
    for (const t of this.tokens.values()) {
      if (t.rotationFamilyId === familyId) t.revoke()
    }
  }
  async countActiveForUser() { return 0 }
  async deleteExpired() { return 0 }
}

class FakeTokenService {
  callCount = 0
  async generateTokenPair(params: { userId: string; tokenVersion: number; rotationFamilyId: string }) {
    this.callCount++
    const now = Math.floor(Date.now() / 1000)
    return TokenPair.create(
      `access-${this.callCount}`,
      `refresh-${this.callCount}`,
      { jti: `jti-${this.callCount}`, issuedAt: now, expiresAt: now + 900, rotationFamilyId: params.rotationFamilyId },
      { jti: `rt-jti-${this.callCount}`, issuedAt: now, expiresAt: now + 2592000, rotationFamilyId: params.rotationFamilyId },
    )
  }
  async verifyAccessToken() { throw new Error('not impl') }
  async generateVerificationToken() { return 'token' }
  async verifyVerificationToken() { return { userId: 'u1', email: 'e@e.com', purpose: 'email_verification' as const } }
}

class FakeAuditLog {
  entries: unknown[] = []
  async log(e: unknown) { this.entries.push(e) }
  async findByUserId() { return [] }
}

describe('RefreshTokenUseCase', () => {
  let userRepo: FakeUserRepo
  let rtRepo: FakeRTRepo
  let tokenService: FakeTokenService
  let auditLog: FakeAuditLog
  let useCase: RefreshTokenUseCase
  let user: User
  let rawToken: string
  let storedToken: RefreshToken

  beforeEach(async () => {
    userRepo = new FakeUserRepo()
    rtRepo = new FakeRTRepo()
    tokenService = new FakeTokenService()
    auditLog = new FakeAuditLog()

    useCase = new RefreshTokenUseCase(
      userRepo as any,
      rtRepo as any,
      tokenService as any,
      auditLog as any,
      { rtExpiryDays: 30 },
    )

    // Create a user and a valid refresh token
    const emailResult = Email.create('user@example.com')
    if (emailResult.isErr()) throw new Error('bad email')
    user = User.create({ id: 'u1', email: emailResult.value, name: 'U', passwordHash: null, pepperVersion: 1 })
    userRepo.users.set(user.id, user)

    rawToken = `raw-token-${crypto.randomUUID()}`
    const tokenHash = await hashToken(rawToken)
    storedToken = RefreshToken.create({
      id: 'rt-1',
      userId: user.id,
      tokenHash,
      rotationFamilyId: 'family-1',
      expiresAt: new Date(Date.now() + 86_400_000),
    })
    rtRepo.tokens.set(storedToken.id, storedToken)
  })

  it('issues new tokens on valid refresh', async () => {
    const result = await useCase.execute({ refreshToken: rawToken })
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.accessToken).toBeTruthy()
      expect(result.value.refreshToken).toBeTruthy()
    }
  })

  it('marks old token as rotated', async () => {
    await useCase.execute({ refreshToken: rawToken })
    expect(storedToken.rotatedAt).toBeInstanceOf(Date)
  })

  it('creates a new refresh token in DB', async () => {
    await useCase.execute({ refreshToken: rawToken })
    expect(rtRepo.tokens.size).toBe(2)
  })

  it('rejects unknown token', async () => {
    const result = await useCase.execute({ refreshToken: 'unknown-token' })
    expect(result.isErr()).toBe(true)
    expect(result.isErr() && result.error.code).toBe('INVALID_TOKEN')
  })

  it('rejects expired token', async () => {
    const expiredToken = RefreshToken.create({
      id: 'rt-expired',
      userId: user.id,
      tokenHash: await hashToken('expired-raw'),
      rotationFamilyId: 'family-1',
      expiresAt: new Date(Date.now() - 1000),
    })
    rtRepo.tokens.set(expiredToken.id, expiredToken)

    const result = await useCase.execute({ refreshToken: 'expired-raw' })
    expect(result.isErr()).toBe(true)
    expect(result.isErr() && result.error.code).toBe('TOKEN_EXPIRED')
  })

  it('detects token reuse and revokes entire family', async () => {
    // Simulate token already rotated (reuse attack)
    storedToken.rotate()
    rtRepo.tokens.set(storedToken.id, storedToken)

    const result = await useCase.execute({ refreshToken: rawToken })

    expect(result.isErr()).toBe(true)
    expect(result.isErr() && result.error.code).toBe('REFRESH_TOKEN_REUSE_DETECTED')
    // Family should be compromised
    expect(rtRepo.families.has('family-1')).toBe(true)
  })

  it('logs audit event on successful refresh', async () => {
    await useCase.execute({ refreshToken: rawToken })
    const entries = auditLog.entries as Array<{ eventType: string }>
    expect(entries.some((e) => e.eventType === 'token_refresh')).toBe(true)
  })

  it('logs suspicious_activity on reuse detection', async () => {
    storedToken.rotate()
    await useCase.execute({ refreshToken: rawToken })
    const entries = auditLog.entries as Array<{ eventType: string; riskLevel: string }>
    const suspicious = entries.find((e) => e.eventType === 'suspicious_activity')
    expect(suspicious).toBeDefined()
    expect(suspicious?.riskLevel).toBe('high')
  })
})
