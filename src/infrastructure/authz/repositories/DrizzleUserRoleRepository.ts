/**
 * DrizzleUserRoleRepository — PostgreSQL implementation of IUserRoleRepository.
 */

import { and, eq } from 'drizzle-orm'
import type { DB } from '../../persistence/db'
import { userRoles as userRolesTable } from '../../persistence/schema'
import type {
  IUserRoleRepository,
  UserRoleAssignment,
} from '../../../domain/authz/repositories/IUserRoleRepository'

export class DrizzleUserRoleRepository implements IUserRoleRepository {
  constructor(private readonly db: DB) {}

  async findRolesForUser(userId: string): Promise<UserRoleAssignment[]> {
    const rows = await this.db
      .select()
      .from(userRolesTable)
      .where(eq(userRolesTable.userId, userId))

    return rows.map((r) => ({
      userId: r.userId,
      roleName: r.roleName,
      assignedAt: r.assignedAt,
      assignedBy: r.assignedBy,
      resourceId: r.resourceId,
      resourceType: r.resourceType,
    }))
  }

  async findUsersForRole(roleName: string): Promise<UserRoleAssignment[]> {
    const rows = await this.db
      .select()
      .from(userRolesTable)
      .where(eq(userRolesTable.roleName, roleName))

    return rows.map((r) => ({
      userId: r.userId,
      roleName: r.roleName,
      assignedAt: r.assignedAt,
      assignedBy: r.assignedBy,
      resourceId: r.resourceId,
      resourceType: r.resourceType,
    }))
  }

  async hasRole(userId: string, roleName: string): Promise<boolean> {
    const [row] = await this.db
      .select({ id: userRolesTable.id })
      .from(userRolesTable)
      .where(
        and(
          eq(userRolesTable.userId, userId),
          eq(userRolesTable.roleName, roleName),
        ),
      )
      .limit(1)

    return !!row
  }

  async assign(
    assignment: Omit<UserRoleAssignment, 'assignedAt'>,
  ): Promise<void> {
    await this.db
      .insert(userRolesTable)
      .values({
        userId: assignment.userId,
        roleName: assignment.roleName,
        assignedBy: assignment.assignedBy,
        resourceId: assignment.resourceId,
        resourceType: assignment.resourceType,
      })
      .onConflictDoNothing()
  }

  async revoke(userId: string, roleName: string): Promise<void> {
    await this.db
      .delete(userRolesTable)
      .where(
        and(
          eq(userRolesTable.userId, userId),
          eq(userRolesTable.roleName, roleName),
        ),
      )
  }

  async revokeAll(userId: string): Promise<void> {
    await this.db
      .delete(userRolesTable)
      .where(eq(userRolesTable.userId, userId))
  }
}
