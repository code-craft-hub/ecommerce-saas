/**
 * Permission Value Object.
 *
 * Format: `resource:action` or `resource:action:scope`
 *
 * Examples:
 *   user:read:self        — read own profile
 *   user:read:any         — read any user (admin)
 *   session:revoke:self   — revoke own sessions
 *   role:assign           — assign roles (no scope = global)
 *   admin:*               — wildcard admin
 *
 * Wildcard rules:
 *   admin:*  matches everything
 *   user:*   matches any action on user resource
 *   user:read matches user:read:self AND user:read:any
 */

export type PermissionString = string & { readonly __brand: 'Permission' }

export class Permission {
  private constructor(
    readonly resource: string,
    readonly action: string,
    readonly scope: string | null,
  ) {}

  static readonly WILDCARD = '*'

  // ---------------------------------------------------------------------------
  // Well-known permissions — single source of truth, no magic strings
  // ---------------------------------------------------------------------------

  // User management
  static readonly USER_READ_SELF = Permission.of('user:read:self')
  static readonly USER_WRITE_SELF = Permission.of('user:write:self')
  static readonly USER_DELETE_SELF = Permission.of('user:delete:self')
  static readonly USER_READ_ANY = Permission.of('user:read:any')
  static readonly USER_WRITE_ANY = Permission.of('user:write:any')
  static readonly USER_DELETE_ANY = Permission.of('user:delete:any')

  // Session management
  static readonly SESSION_READ_SELF = Permission.of('session:read:self')
  static readonly SESSION_REVOKE_SELF = Permission.of('session:revoke:self')
  static readonly SESSION_REVOKE_ANY = Permission.of('session:revoke:any')

  // Role management
  static readonly ROLE_ASSIGN = Permission.of('role:assign')
  static readonly ROLE_REVOKE = Permission.of('role:revoke')
  static readonly ROLE_READ = Permission.of('role:read')

  // Audit log
  static readonly AUDIT_READ = Permission.of('audit:read')

  // Content moderation
  static readonly CONTENT_MODERATE = Permission.of('content:moderate')
  static readonly CONTENT_DELETE = Permission.of('content:delete')

  // Admin wildcard — grants everything
  static readonly ADMIN_ALL = Permission.of('admin:*')

  // ---------------------------------------------------------------------------
  // Factory
  // ---------------------------------------------------------------------------

  static of(raw: string): Permission {
    const parts = raw.split(':')
    if (parts.length < 2) {
      throw new Error(`Invalid permission format: "${raw}". Expected resource:action[:scope]`)
    }
    const [resource, action, scope] = parts
    return new Permission(resource!, action!, scope ?? null)
  }

  static create(resource: string, action: string, scope?: string): Permission {
    return new Permission(resource, action, scope ?? null)
  }

  // ---------------------------------------------------------------------------
  // Matching logic
  // ---------------------------------------------------------------------------

  /**
   * Returns true if `this` permission grants the `required` permission.
   * Supports wildcards at any segment.
   */
  grants(required: Permission): boolean {
    // admin:* grants everything
    if (this.resource === 'admin' && this.action === Permission.WILDCARD) return true

    // resource wildcard: user:* grants any user:x:y
    if (this.resource === required.resource && this.action === Permission.WILDCARD) return true

    // Exact resource + action match
    if (this.resource !== required.resource || this.action !== required.action) return false

    // No scope on this permission → grants all scopes of this action
    if (this.scope === null) return true

    // Scope wildcard
    if (this.scope === Permission.WILDCARD) return true

    // :any scope grants :self
    if (this.scope === 'any' && required.scope === 'self') return true

    // Exact scope match
    return this.scope === required.scope
  }

  toString(): string {
    return this.scope
      ? `${this.resource}:${this.action}:${this.scope}`
      : `${this.resource}:${this.action}`
  }

  equals(other: Permission): boolean {
    return this.toString() === other.toString()
  }
}
