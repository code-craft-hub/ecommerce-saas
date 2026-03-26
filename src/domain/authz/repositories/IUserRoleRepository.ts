/**
 * IUserRoleRepository — manages user ↔ role assignments.
 * The join table between users and roles (RBAC subject assignments).
 */

export interface UserRoleAssignment {
  userId: string
  roleName: string
  assignedAt: Date
  assignedBy: string | null
  /** Optional — if the role assignment is scoped to a resource/tenant */
  resourceId: string | null
  resourceType: string | null
}

export interface IUserRoleRepository {
  findRolesForUser(userId: string): Promise<UserRoleAssignment[]>
  findUsersForRole(roleName: string): Promise<UserRoleAssignment[]>
  hasRole(userId: string, roleName: string): Promise<boolean>
  assign(assignment: Omit<UserRoleAssignment, 'assignedAt'>): Promise<void>
  revoke(userId: string, roleName: string): Promise<void>
  revokeAll(userId: string): Promise<void>
}
