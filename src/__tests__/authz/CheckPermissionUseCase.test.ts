import { describe, it, expect, beforeEach } from 'vitest'
import { CheckPermissionUseCase } from '@/application/authz/usecases/CheckPermissionUseCase'
import { Permission } from '@/domain/authz/value-objects/Permission'
import { User } from '@/domain/auth/entities/User'
import { Email } from '@/domain/auth/value-objects/Email'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IUserRoleRepository, UserRoleAssignment } from '@/domain/authz/repositories/IUserRoleRepository'
import type { IAuthorizationService } from '@/domain/authz/services/IAuthorizationService'
import type { AuthorizationContext } from '@/domain/authz/value-objects/AuthorizationContext'
import type { AuthorizationDecision } from '@/domain/authz/types/AuthorizationDecision'
import { ok, err, DomainError } from '@/domain/shared/Result'
import type { Result } from '@/domain/shared/Result'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

function makeUser(overrides: { id?: string; emailVerified?: boolean; tokenVersion?: number; deleted?: boolean } = {}) {
  const emailResult = Email.create('alice@example.com')
  if (emailResult.isErr()) throw new Error('bad email')

  const user = User.reconstitute({
    id: overrides.id ?? 'user-uuid-1',
    email: emailResult.value,
    emailVerified: overrides.emailVerified ?? true,
    passwordHash: null,
    passwordPepperVersion: 1,
    tokenVersion: overrides.tokenVersion ?? 1,
    name: 'Alice',
    createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    updatedAt: new Date(),
    deletedAt: overrides.deleted ? new Date() : null,
    metadata: {},
  })
  return user
}

class FakeUserRepo implements IUserRepository {
  private store = new Map<string, User>()

  seed(user: User) { this.store.set(user.id, user) }

  async findById(id: string) { return this.store.get(id) ?? null }
  async findByEmail(_email: string) { return null }
  async save(user: User) { this.store.set(user.id, user) }
  async update(user: User) { this.store.set(user.id, user) }
  async delete(id: string) { this.store.delete(id) }
}

class FakeUserRoleRepo implements IUserRoleRepository {
  private assignments: UserRoleAssignment[] = []

  seed(userId: string, ...roleNames: string[]) {
    for (const roleName of roleNames) {
      this.assignments.push({
        userId,
        roleName,
        assignedAt: new Date(),
        assignedBy: null,
        resourceId: null,
        resourceType: null,
      })
    }
  }

  async findRolesForUser(userId: string) {
    return this.assignments.filter((a) => a.userId === userId)
  }
  async findUsersForRole(roleName: string) {
    return this.assignments.filter((a) => a.roleName === roleName)
  }
  async hasRole(userId: string, roleName: string) {
    return this.assignments.some((a) => a.userId === userId && a.roleName === roleName)
  }
  async assign(a: Omit<UserRoleAssignment, 'assignedAt'>) {
    this.assignments.push({ ...a, assignedAt: new Date() })
  }
  async revoke(userId: string, roleName: string) {
    this.assignments = this.assignments.filter(
      (a) => !(a.userId === userId && a.roleName === roleName),
    )
  }
  async revokeAll(userId: string) {
    this.assignments = this.assignments.filter((a) => a.userId !== userId)
  }
}

class AlwaysAllowAuthzService implements IAuthorizationService {
  async authorize(_ctx: AuthorizationContext): Promise<Result<AuthorizationDecision, DomainError>> {
    return ok({ effect: 'Allow', reason: 'test allow', source: 'RBAC' })
  }
  async isAuthorized(_ctx: AuthorizationContext) { return true }
}

class AlwaysDenyAuthzService implements IAuthorizationService {
  async authorize(_ctx: AuthorizationContext): Promise<Result<AuthorizationDecision, DomainError>> {
    return ok({ effect: 'Deny', reason: 'test deny', source: 'RBAC' })
  }
  async isAuthorized(_ctx: AuthorizationContext) { return false }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('CheckPermissionUseCase', () => {
  let userRepo: FakeUserRepo
  let userRoleRepo: FakeUserRoleRepo
  let user: User

  beforeEach(() => {
    userRepo = new FakeUserRepo()
    userRoleRepo = new FakeUserRoleRepo()
    user = makeUser()
    userRepo.seed(user)
    userRoleRepo.seed(user.id, 'user')
  })

  it('returns Ok(allowed) when authorization service allows', async () => {
    const useCase = new CheckPermissionUseCase(
      userRepo,
      userRoleRepo,
      new AlwaysAllowAuthzService(),
    )

    const result = await useCase.execute({
      userId: user.id,
      tokenVersion: 1,
      action: Permission.USER_READ_SELF.toString(),
      resource: { type: 'user', id: user.id, ownerId: user.id, custom: {} },
    })

    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.allowed).toBe(true)
    }
  })

  it('returns Err(PERMISSION_DENIED) when authorization service denies', async () => {
    const useCase = new CheckPermissionUseCase(
      userRepo,
      userRoleRepo,
      new AlwaysDenyAuthzService(),
    )

    const result = await useCase.execute({
      userId: user.id,
      tokenVersion: 1,
      action: Permission.AUDIT_READ.toString(),
      resource: { type: 'audit', id: null, ownerId: null, custom: {} },
    })

    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error.code).toBe('PERMISSION_DENIED')
    }
  })

  it('returns Err(USER_NOT_FOUND) for unknown userId', async () => {
    const useCase = new CheckPermissionUseCase(
      userRepo,
      userRoleRepo,
      new AlwaysAllowAuthzService(),
    )

    const result = await useCase.execute({
      userId: 'non-existent-uuid',
      tokenVersion: 1,
      action: Permission.USER_READ_SELF.toString(),
      resource: { type: 'user', id: null, ownerId: null, custom: {} },
    })

    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error.code).toBe('USER_NOT_FOUND')
    }
  })

  it('returns Err(TOKEN_REVOKED) when tokenVersion is stale', async () => {
    // User has tokenVersion 2 (sessions were revoked) but request claims version 1
    const staleUser = makeUser({ tokenVersion: 2 })
    userRepo.seed(staleUser)

    const useCase = new CheckPermissionUseCase(
      userRepo,
      userRoleRepo,
      new AlwaysAllowAuthzService(),
    )

    const result = await useCase.execute({
      userId: staleUser.id,
      tokenVersion: 1, // stale
      action: Permission.USER_READ_SELF.toString(),
      resource: { type: 'user', id: staleUser.id, ownerId: staleUser.id, custom: {} },
    })

    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error.code).toBe('TOKEN_REVOKED')
    }
  })

  it('returns Err(USER_NOT_FOUND) for soft-deleted user', async () => {
    const deletedUser = makeUser({ deleted: true })
    userRepo.seed(deletedUser)

    const useCase = new CheckPermissionUseCase(
      userRepo,
      userRoleRepo,
      new AlwaysAllowAuthzService(),
    )

    const result = await useCase.execute({
      userId: deletedUser.id,
      tokenVersion: 1,
      action: Permission.USER_READ_SELF.toString(),
      resource: { type: 'user', id: deletedUser.id, ownerId: deletedUser.id, custom: {} },
    })

    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error.code).toBe('USER_NOT_FOUND')
    }
  })

  it('returns Err(INTERNAL_ERROR) for invalid permission format', async () => {
    const useCase = new CheckPermissionUseCase(
      userRepo,
      userRoleRepo,
      new AlwaysAllowAuthzService(),
    )

    const result = await useCase.execute({
      userId: user.id,
      tokenVersion: 1,
      action: 'not-valid-permission',
      resource: { type: 'user', id: null, ownerId: null, custom: {} },
    })

    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error.code).toBe('INTERNAL_ERROR')
    }
  })
})
