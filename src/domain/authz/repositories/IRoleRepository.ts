/**
 * IRoleRepository — storage-agnostic interface for Role persistence.
 * Implemented in infrastructure layer by DrizzleRoleRepository.
 */

import type { Role } from '@/domain/authz/value-objects/Role'

export interface IRoleRepository {
  findByName(name: string): Promise<Role | null>
  findAll(): Promise<Role[]>
  save(role: Role): Promise<void>
  /** Seed built-in roles if they do not exist yet. */
  seedBuiltinRoles(): Promise<void>
}
