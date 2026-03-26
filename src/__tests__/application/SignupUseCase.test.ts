import { describe, it, expect, vi, beforeEach } from 'vitest'
import { SignupUseCase } from '@/application/auth/signup/SignupUseCase'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IRefreshTokenRepository } from '@/domain/auth/repositories/IRefreshTokenRepository'
import type { IPasswordHashingService } from '@/domain/auth/services/IPasswordHashingService'
import type { ITokenGenerationService } from '@/domain/auth/services/ITokenGenerationService'
import type { ISessionCache } from '@/domain/auth/services/ISessionCache'
import type { IEmailService } from '@/domain/auth/services/IEmailService'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'
import { EventBus } from '@/application/shared/EventBus'
import { HashedPassword } from '@/domain/auth/value-objects/Password'
import { TokenPair } from '@/domain/auth/value-objects/TokenPair'

// ---------------------------------------------------------------------------
// Minimal in-memory fakes (no mocks — pure test doubles)
// ---------------------------------------------------------------------------

class InMemoryUserRepository implements IUserRepository {
  users = new Map<string, import('@/domain/auth/entities/User').User>()

  async findById(id: string) {
    return this.users.get(id) ?? null
  }
  async findByEmail(email: string) {
    for (const u of this.users.values()) {
      if (u.email.value === email) return u
    }
    return null
  }
  async save(user: import('@/domain/auth/entities/User').User) {
    this.users.set(user.id, user)
  }
  async update(user: import('@/domain/auth/entities/User').User) {
    this.users.set(user.id, user)
  }
  async delete(id: string) {
    this.users.delete(id)
  }
}

class InMemoryRefreshTokenRepository implements IRefreshTokenRepository {
  tokens = new Map<string, import('@/domain/auth/entities/RefreshToken').RefreshToken>()

  async findByHash(hash: string) {
    for (const t of this.tokens.values()) {
      if (t.tokenHash === hash) return t
    }
    return null
  }
  async findById(id: string) { return this.tokens.get(id) ?? null }
  async findActiveByUserId(userId: string) {
    return Array.from(this.tokens.values()).filter((t) => t.userId === userId && t.isValid)
  }
  async save(token: import('@/domain/auth/entities/RefreshToken').RefreshToken) {
    this.tokens.set(token.id, token)
  }
  async update(token: import('@/domain/auth/entities/RefreshToken').RefreshToken) {
    this.tokens.set(token.id, token)
  }
  async revokeAllForUser(userId: string) {
    let count = 0
    for (const t of this.tokens.values()) {
      if (t.userId === userId) { t.revoke(); count++ }
    }
    return count
  }
  async revokeFamilyTokens(familyId: string) {
    for (const t of this.tokens.values()) {
      if (t.rotationFamilyId === familyId) t.revoke()
    }
  }
  async countActiveForUser(userId: string) {
    return Array.from(this.tokens.values()).filter((t) => t.userId === userId && t.isValid).length
  }
  async deleteExpired() { return 0 }
}

class FakePasswordHasher implements IPasswordHashingService {
  currentPepperVersion = 1
  async hash(_pw: import('@/domain/auth/value-objects/Password').PlaintextPassword) {
    return HashedPassword.fromHash('$argon2id$fake')
  }
  async verify(_pw: import('@/domain/auth/value-objects/Password').PlaintextPassword, _hash: import('@/domain/auth/value-objects/Password').HashedPassword) {
    return true
  }
}

class FakeTokenService implements ITokenGenerationService {
  async generateTokenPair(params: { userId: string; tokenVersion: number; rotationFamilyId: string }) {
    const now = Math.floor(Date.now() / 1000)
    return TokenPair.create(
      'fake-access-token',
      'fake-refresh-token',
      { jti: crypto.randomUUID(), issuedAt: now, expiresAt: now + 900, rotationFamilyId: params.rotationFamilyId },
      { jti: crypto.randomUUID(), issuedAt: now, expiresAt: now + 2592000, rotationFamilyId: params.rotationFamilyId },
    )
  }
  async verifyAccessToken(_token: string): Promise<import('@/domain/auth/services/ITokenGenerationService').AccessTokenClaims> {
    throw new Error('not implemented')
  }
  async generateVerificationToken(_payload: { userId: string; email: string; purpose: 'email_verification' | 'password_reset' }) {
    return 'fake-verification-token'
  }
  async verifyVerificationToken(_token: string) {
    return { userId: 'u1', email: 'test@example.com', purpose: 'email_verification' as const }
  }
}

class FakeSessionCache implements ISessionCache {
  private store = new Map<string, string>()
  async denylistToken(jti: string, ttl: number) { this.store.set(`deny:${jti}`, '1') }
  async isTokenDenylisted(jti: string) { return this.store.has(`deny:${jti}`) }
  async setSession() {}
  async clearUserSessions() {}
  async setOAuthState(state: string, data: string) { this.store.set(`oauth:${state}`, data) }
  async consumeOAuthState(state: string) {
    const v = this.store.get(`oauth:${state}`) ?? null
    this.store.delete(`oauth:${state}`)
    return v
  }
  async setVerificationCode(key: string, value: string) { this.store.set(key, value) }
  async getVerificationCode(key: string) { return this.store.get(key) ?? null }
  async deleteVerificationCode(key: string) { this.store.delete(key) }
}

class FakeEmailService implements IEmailService {
  sent: unknown[] = []
  async sendVerificationEmail(p: object) { this.sent.push({ type: 'verify', ...p }) }
  async sendPasswordResetEmail(p: object) { this.sent.push(p) }
  async sendPasswordChangedNotification(p: object) { this.sent.push(p) }
  async sendNewOAuthLinkNotification(p: object) { this.sent.push(p) }
  async sendSuspiciousActivityAlert(p: object) { this.sent.push(p) }
}

class FakeAuditLog implements IAuditLogRepository {
  entries: unknown[] = []
  async log(e: unknown) { this.entries.push(e) }
  async findByUserId() { return [] }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SignupUseCase', () => {
  let userRepo: InMemoryUserRepository
  let refreshTokenRepo: InMemoryRefreshTokenRepository
  let passwordHasher: FakePasswordHasher
  let tokenService: FakeTokenService
  let sessionCache: FakeSessionCache
  let emailService: FakeEmailService
  let auditLog: FakeAuditLog
  let eventBus: EventBus
  let useCase: SignupUseCase

  beforeEach(() => {
    userRepo = new InMemoryUserRepository()
    refreshTokenRepo = new InMemoryRefreshTokenRepository()
    passwordHasher = new FakePasswordHasher()
    tokenService = new FakeTokenService()
    sessionCache = new FakeSessionCache()
    emailService = new FakeEmailService()
    auditLog = new FakeAuditLog()
    eventBus = new EventBus()

    useCase = new SignupUseCase(
      userRepo,
      refreshTokenRepo,
      passwordHasher,
      tokenService,
      sessionCache,
      emailService,
      auditLog,
      eventBus,
      { baseUrl: 'http://localhost:3000', rtExpiryDays: 30 },
    )
  })

  it('creates user and returns access token', async () => {
    const result = await useCase.execute({
      email: 'alice@example.com',
      password: 'SecureP@ssw0rd!',
      name: 'Alice',
    })

    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.accessToken).toBe('fake-access-token')
      expect(result.value.user.email).toBe('alice@example.com')
      expect(result.value.user.emailVerified).toBe(false)
    }
  })

  it('persists user to repository', async () => {
    await useCase.execute({
      email: 'alice@example.com',
      password: 'SecureP@ssw0rd!',
      name: 'Alice',
    })

    const user = await userRepo.findByEmail('alice@example.com')
    expect(user).not.toBeNull()
    expect(user?.name).toBe('Alice')
  })

  it('persists refresh token', async () => {
    await useCase.execute({
      email: 'alice@example.com',
      password: 'SecureP@ssw0rd!',
      name: 'Alice',
    })

    expect(refreshTokenRepo.tokens.size).toBe(1)
  })

  it('rejects duplicate email', async () => {
    await useCase.execute({
      email: 'alice@example.com',
      password: 'SecureP@ssw0rd!',
      name: 'Alice',
    })
    const result = await useCase.execute({
      email: 'alice@example.com',
      password: 'AnotherP@ssw0rd!1',
      name: 'Alice2',
    })

    expect(result.isErr()).toBe(true)
    expect(result.isErr() && result.error.code).toBe('USER_ALREADY_EXISTS')
  })

  it('rejects invalid email format', async () => {
    const result = await useCase.execute({
      email: 'not-an-email',
      password: 'SecureP@ssw0rd!',
      name: 'Alice',
    })

    expect(result.isErr()).toBe(true)
    expect(result.isErr() && result.error.code).toBe('INVALID_EMAIL')
  })

  it('rejects weak password', async () => {
    const result = await useCase.execute({
      email: 'alice@example.com',
      password: 'weak',
      name: 'Alice',
    })

    expect(result.isErr()).toBe(true)
    expect(result.isErr() && result.error.code).toBe('WEAK_PASSWORD')
  })

  it('logs signup audit event', async () => {
    await useCase.execute({
      email: 'alice@example.com',
      password: 'SecureP@ssw0rd!',
      name: 'Alice',
    })

    expect(auditLog.entries).toHaveLength(1)
    expect((auditLog.entries[0] as { eventType: string }).eventType).toBe('signup')
  })

  it('publishes UserCreatedEvent', async () => {
    const publishedEvents: string[] = []
    eventBus.subscribe('auth.user.created', async (e) => {
      publishedEvents.push(e.eventName)
    })

    await useCase.execute({
      email: 'alice@example.com',
      password: 'SecureP@ssw0rd!',
      name: 'Alice',
    })

    expect(publishedEvents).toContain('auth.user.created')
  })
})
