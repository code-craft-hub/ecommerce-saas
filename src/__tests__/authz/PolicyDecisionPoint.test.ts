import { describe, it, expect, beforeEach } from 'vitest'
import { PolicyDecisionPoint } from '../../infrastructure/authz/pdp/PolicyDecisionPoint'
import { RbacPolicy } from '../../infrastructure/authz/policies/RbacPolicy'
import { AbacPolicy } from '../../infrastructure/authz/policies/AbacPolicy'
import { PbacPolicy } from '../../infrastructure/authz/policies/PbacPolicy'
import { AuthorizationContext } from '../../domain/authz/value-objects/AuthorizationContext'
import { Permission } from '../../domain/authz/value-objects/Permission'
import type { IRoleRepository } from '../../domain/authz/repositories/IRoleRepository'
import { Role } from '../../domain/authz/value-objects/Role'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

class InMemoryRoleRepository implements IRoleRepository {
  private roles = new Map<string, Role>()

  constructor() {
    // Seed built-in roles
    for (const def of Role.DEFINITIONS) {
      const role = Role.create({
        name: def.name,
        displayName: def.displayName,
        description: def.description,
        permissions: def.permissions,
        isSystem: def.isSystem,
      })
      this.roles.set(role.name, role)
    }
  }

  async findByName(name: string): Promise<Role | null> {
    return this.roles.get(name) ?? null
  }

  async findAll(): Promise<Role[]> {
    return Array.from(this.roles.values())
  }

  async save(role: Role): Promise<void> {
    this.roles.set(role.name, role)
  }

  async seedBuiltinRoles(): Promise<void> {
    // Already seeded in constructor
  }
}

function makeContext(overrides: {
  roles?: string[]
  action?: Permission
  emailVerified?: boolean
  ipReputation?: 'clean' | 'suspicious' | 'blocked' | 'unknown'
  ownerId?: string | null
  recentFailedLogins?: number
  createdAt?: Date
}) {
  return AuthorizationContext.create({
    subject: {
      userId: 'user-123',
      roles: overrides.roles ?? ['user'],
      emailVerified: overrides.emailVerified ?? true,
      tokenVersion: 1,
      createdAt: overrides.createdAt ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    },
    action: overrides.action ?? Permission.USER_READ_SELF,
    resource: {
      type: 'user',
      id: 'user-123',
      ownerId: overrides.ownerId ?? 'user-123',
      custom: {},
    },
    environment: {
      ipAddress: '1.2.3.4',
      ipReputation: overrides.ipReputation ?? 'clean',
      recentFailedLogins: overrides.recentFailedLogins ?? 0,
    },
  })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PolicyDecisionPoint — deny-overrides', () => {
  let roleRepo: InMemoryRoleRepository
  let pdp: PolicyDecisionPoint

  beforeEach(() => {
    roleRepo = new InMemoryRoleRepository()
    pdp = new PolicyDecisionPoint([
      new PbacPolicy(),
      new AbacPolicy(),
      new RbacPolicy(roleRepo),
    ])
  })

  it('allows user:read:self for "user" role with clean IP and verified email', async () => {
    const ctx = makeContext({ roles: ['user'], action: Permission.USER_READ_SELF })
    const decision = await pdp.decide(ctx)
    expect(decision.effect).toBe('Allow')
    expect(decision.source).toBe('PDP')
  })

  it('denies when no role grants the permission', async () => {
    const ctx = makeContext({ roles: ['user'], action: Permission.AUDIT_READ })
    const decision = await pdp.decide(ctx)
    expect(decision.effect).toBe('Deny')
  })

  it('allows admin:* role to access audit:read', async () => {
    const ctx = makeContext({ roles: ['admin'], action: Permission.AUDIT_READ })
    const decision = await pdp.decide(ctx)
    expect(decision.effect).toBe('Allow')
  })

  it('allows admin:* role to access role:assign', async () => {
    const ctx = makeContext({ roles: ['admin'], action: Permission.ROLE_ASSIGN })
    const decision = await pdp.decide(ctx)
    expect(decision.effect).toBe('Allow')
  })

  it('ABAC denies blocked IP regardless of role', async () => {
    const ctx = makeContext({
      roles: ['admin'],
      action: Permission.USER_READ_ANY,
      ipReputation: 'blocked',
    })
    const decision = await pdp.decide(ctx)
    expect(decision.effect).toBe('Deny')
    expect(decision.reason).toMatch(/block/)
  })

  it('ABAC denies suspicious IP for write operations', async () => {
    const ctx = makeContext({
      roles: ['user'],
      action: Permission.USER_WRITE_SELF,
      ipReputation: 'suspicious',
      emailVerified: true,
    })
    const decision = await pdp.decide(ctx)
    expect(decision.effect).toBe('Deny')
  })

  it('ABAC denies unverified email for write operations', async () => {
    const ctx = makeContext({
      roles: ['user'],
      action: Permission.USER_WRITE_SELF,
      emailVerified: false,
    })
    const decision = await pdp.decide(ctx)
    expect(decision.effect).toBe('Deny')
    expect(decision.reason).toMatch(/email/i)
  })

  it('PBAC denies service accounts from write operations', async () => {
    const ctx = makeContext({
      roles: ['service'],
      action: Permission.USER_WRITE_ANY,
      emailVerified: true,
    })
    const decision = await pdp.decide(ctx)
    expect(decision.effect).toBe('Deny')
    expect(decision.reason).toMatch(/service/i)
  })

  it('PBAC allows service accounts read access', async () => {
    const ctx = makeContext({
      roles: ['service'],
      action: Permission.USER_READ_ANY,
      emailVerified: true,
    })
    const decision = await pdp.decide(ctx)
    expect(decision.effect).toBe('Allow')
  })

  it('fails closed when all evaluators return NotApplicable', async () => {
    // Use an empty PDP (no evaluators)
    const emptyPdp = new PolicyDecisionPoint([])
    const ctx = makeContext({})
    const decision = await emptyPdp.decide(ctx)
    expect(decision.effect).toBe('Deny')
    expect(decision.reason).toMatch(/default deny/i)
  })
})

describe('PolicyDecisionPoint — permit-overrides', () => {
  it('allows if any evaluator allows, even if others deny', async () => {
    const roleRepo = new InMemoryRoleRepository()
    const pdp = new PolicyDecisionPoint(
      [new RbacPolicy(roleRepo)],
      'permit-overrides',
    )
    const ctx = makeContext({ roles: ['admin'], action: Permission.AUDIT_READ })
    const decision = await pdp.decide(ctx)
    expect(decision.effect).toBe('Allow')
  })
})
