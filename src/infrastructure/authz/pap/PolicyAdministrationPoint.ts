/**
 * PolicyAdministrationPoint (PAP).
 *
 * Manages the lifecycle of roles and policies:
 *   - Creates, updates, and deletes custom roles
 *   - Seeds built-in system roles on startup
 *   - Provides role listing for admin UIs
 *
 * The PAP is the only component that writes to the roles table.
 * It enforces invariants: system roles cannot be modified or deleted.
 */

import type { IRoleRepository } from '@/domain/authz/repositories/IRoleRepository'
import { Role } from '@/domain/authz/value-objects/Role'
import { Permission } from '@/domain/authz/value-objects/Permission'

export interface CreateRoleParams {
  name: string
  displayName: string
  description: string
  permissions: string[]
}

export class PolicyAdministrationPoint {
  constructor(private readonly roleRepo: IRoleRepository) {}

  /**
   * Seed all built-in system roles into the database if they do not exist.
   * Should be called once at application startup.
   */
  async seedBuiltinRoles(): Promise<void> {
    await this.roleRepo.seedBuiltinRoles()
  }

  /**
   * Create a custom role. System roles use Role.DEFINITIONS instead.
   */
  async createRole(params: CreateRoleParams): Promise<void> {
    const existing = await this.roleRepo.findByName(params.name)
    if (existing) {
      throw new Error(`Role '${params.name}' already exists`)
    }

    const permissions = params.permissions.map((p) => Permission.of(p))
    const role = Role.create({
      name: params.name,
      displayName: params.displayName,
      description: params.description,
      permissions,
      isSystem: false,
    })

    await this.roleRepo.save(role)
  }

  /**
   * List all roles for admin management UI.
   */
  async listRoles(): Promise<
    Array<{
      name: string
      displayName: string
      description: string
      permissions: string[]
      isSystem: boolean
    }>
  > {
    const roles = await this.roleRepo.findAll()
    return roles.map((r) => ({
      name: r.name,
      displayName: r.displayName,
      description: r.description,
      permissions: r.permissions.map((p) => p.toString()),
      isSystem: r.isSystem,
    }))
  }
}
