/**
 * DrizzleRoleRepository — PostgreSQL implementation of IRoleRepository.
 */

import { eq } from 'drizzle-orm'
import type { DB } from '../../persistence/db'
import { roles as rolesTable } from '../../persistence/schema'
import type { IRoleRepository } from '../../../domain/authz/repositories/IRoleRepository'
import { Role } from '../../../domain/authz/value-objects/Role'

export class DrizzleRoleRepository implements IRoleRepository {
  constructor(private readonly db: DB) {}

  async findByName(name: string): Promise<Role | null> {
    const [row] = await this.db
      .select()
      .from(rolesTable)
      .where(eq(rolesTable.name, name))
      .limit(1)

    if (!row) return null
    return this.toDomain(row)
  }

  async findAll(): Promise<Role[]> {
    const rows = await this.db.select().from(rolesTable)
    return rows.map((r) => this.toDomain(r))
  }

  async save(role: Role): Promise<void> {
    await this.db
      .insert(rolesTable)
      .values({
        name: role.name,
        displayName: role.displayName,
        description: role.description,
        permissions: role.permissions.map((p) => p.toString()),
        isSystem: role.isSystem,
      })
      .onConflictDoNothing()
  }

  async seedBuiltinRoles(): Promise<void> {
    for (const def of Role.DEFINITIONS) {
      const existing = await this.findByName(def.name)
      if (existing) continue

      const role = Role.create({
        name: def.name,
        displayName: def.displayName,
        description: def.description,
        permissions: def.permissions,
        isSystem: def.isSystem,
      })
      await this.save(role)
    }
  }

  private toDomain(row: {
    name: string
    displayName: string
    description: string
    permissions: unknown
    isSystem: boolean
  }): Role {
    const permStrings = Array.isArray(row.permissions)
      ? (row.permissions as string[])
      : []
    return Role.reconstitute({
      name: row.name,
      displayName: row.displayName,
      description: row.description,
      permissionStrings: permStrings,
      isSystem: row.isSystem,
    })
  }
}
