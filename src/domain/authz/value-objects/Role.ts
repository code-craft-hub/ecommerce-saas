/**
 * Role Value Object.
 *
 * A role is a named set of permissions, part of the RBAC framework.
 * Roles are immutable once created — changes are modeled as new role versions.
 *
 * Built-in roles are defined as static constants and seeded at startup.
 * Custom roles can be created at runtime via PolicyAdministrationPoint.
 */

import { Permission } from './Permission'

export type RoleName = string & { readonly __brand: 'RoleName' }

export class Role {
  private constructor(
    readonly name: string,
    readonly displayName: string,
    readonly description: string,
    private readonly _permissions: ReadonlySet<string>,
    readonly isSystem: boolean,
  ) {}

  // ---------------------------------------------------------------------------
  // Built-in system roles (seeded into DB on first run)
  // ---------------------------------------------------------------------------

  static readonly DEFINITIONS: ReadonlyArray<{
    name: string
    displayName: string
    description: string
    permissions: Permission[]
    isSystem: boolean
  }> = [
    {
      name: 'user',
      displayName: 'User',
      description: 'Default role for all registered users',
      isSystem: true,
      permissions: [
        Permission.USER_READ_SELF,
        Permission.USER_WRITE_SELF,
        Permission.USER_DELETE_SELF,
        Permission.SESSION_READ_SELF,
        Permission.SESSION_REVOKE_SELF,
      ],
    },
    {
      name: 'moderator',
      displayName: 'Moderator',
      description: 'Content moderation capabilities',
      isSystem: true,
      permissions: [
        Permission.USER_READ_SELF,
        Permission.USER_WRITE_SELF,
        Permission.USER_DELETE_SELF,
        Permission.SESSION_READ_SELF,
        Permission.SESSION_REVOKE_SELF,
        Permission.USER_READ_ANY,
        Permission.CONTENT_MODERATE,
        Permission.CONTENT_DELETE,
      ],
    },
    {
      name: 'admin',
      displayName: 'Administrator',
      description: 'Full system access',
      isSystem: true,
      permissions: [Permission.ADMIN_ALL],
    },
    {
      name: 'service',
      displayName: 'Service Account',
      description: 'Machine-to-machine API access',
      isSystem: true,
      permissions: [
        Permission.USER_READ_ANY,
        Permission.AUDIT_READ,
        Permission.ROLE_READ,
      ],
    },
  ]

  // ---------------------------------------------------------------------------
  // Factory
  // ---------------------------------------------------------------------------

  static create(params: {
    name: string
    displayName: string
    description: string
    permissions: Permission[]
    isSystem?: boolean
  }): Role {
    return new Role(
      params.name,
      params.displayName,
      params.description,
      new Set(params.permissions.map((p) => p.toString())),
      params.isSystem ?? false,
    )
  }

  static reconstitute(params: {
    name: string
    displayName: string
    description: string
    permissionStrings: string[]
    isSystem: boolean
  }): Role {
    return new Role(
      params.name,
      params.displayName,
      params.description,
      new Set(params.permissionStrings),
      params.isSystem,
    )
  }

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  get permissions(): Permission[] {
    return Array.from(this._permissions).map((p) => Permission.of(p))
  }

  hasPermission(required: Permission): boolean {
    for (const p of this._permissions) {
      if (Permission.of(p).grants(required)) return true
    }
    return false
  }

  equals(other: Role): boolean {
    return this.name === other.name
  }
}
