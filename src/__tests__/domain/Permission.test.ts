import { describe, it, expect } from 'vitest'
import { Permission } from '../../domain/authz/value-objects/Permission'

describe('Permission', () => {
  describe('of()', () => {
    it('parses resource:action format', () => {
      const p = Permission.of('user:read')
      expect(p.resource).toBe('user')
      expect(p.action).toBe('read')
      expect(p.scope).toBeNull()
    })

    it('parses resource:action:scope format', () => {
      const p = Permission.of('user:read:self')
      expect(p.resource).toBe('user')
      expect(p.action).toBe('read')
      expect(p.scope).toBe('self')
    })

    it('throws on invalid format', () => {
      expect(() => Permission.of('onlyone')).toThrow()
    })
  })

  describe('toString()', () => {
    it('returns resource:action without scope', () => {
      expect(Permission.of('user:read').toString()).toBe('user:read')
    })

    it('returns resource:action:scope with scope', () => {
      expect(Permission.of('user:read:self').toString()).toBe('user:read:self')
    })
  })

  describe('grants()', () => {
    it('admin:* grants everything', () => {
      const adminAll = Permission.of('admin:*')
      expect(adminAll.grants(Permission.of('user:read:self'))).toBe(true)
      expect(adminAll.grants(Permission.of('role:assign'))).toBe(true)
      expect(adminAll.grants(Permission.of('audit:read'))).toBe(true)
    })

    it('resource wildcard grants any action on that resource', () => {
      const userAll = Permission.of('user:*')
      expect(userAll.grants(Permission.of('user:read'))).toBe(true)
      expect(userAll.grants(Permission.of('user:write:self'))).toBe(true)
      expect(userAll.grants(Permission.of('session:read'))).toBe(false)
    })

    it(':any scope grants :self scope', () => {
      const anyPerm = Permission.of('user:read:any')
      expect(anyPerm.grants(Permission.of('user:read:self'))).toBe(true)
      expect(anyPerm.grants(Permission.of('user:read:any'))).toBe(true)
    })

    it(':self scope does NOT grant :any scope', () => {
      const selfPerm = Permission.of('user:read:self')
      expect(selfPerm.grants(Permission.of('user:read:any'))).toBe(false)
    })

    it('no scope grants both :self and :any', () => {
      const noScope = Permission.of('user:read')
      expect(noScope.grants(Permission.of('user:read:self'))).toBe(true)
      expect(noScope.grants(Permission.of('user:read:any'))).toBe(true)
    })

    it('exact match grants exact', () => {
      const p = Permission.of('session:revoke:self')
      expect(p.grants(Permission.of('session:revoke:self'))).toBe(true)
      expect(p.grants(Permission.of('session:revoke:any'))).toBe(false)
    })

    it('different resource does not grant', () => {
      expect(
        Permission.of('user:read').grants(Permission.of('session:read')),
      ).toBe(false)
    })

    it('different action does not grant', () => {
      expect(
        Permission.of('user:read').grants(Permission.of('user:write')),
      ).toBe(false)
    })
  })

  describe('static constants', () => {
    it('USER_READ_SELF is user:read:self', () => {
      expect(Permission.USER_READ_SELF.toString()).toBe('user:read:self')
    })

    it('ADMIN_ALL is admin:*', () => {
      expect(Permission.ADMIN_ALL.toString()).toBe('admin:*')
    })

    it('ADMIN_ALL grants USER_READ_SELF', () => {
      expect(Permission.ADMIN_ALL.grants(Permission.USER_READ_SELF)).toBe(true)
    })

    it('ADMIN_ALL grants ROLE_ASSIGN', () => {
      expect(Permission.ADMIN_ALL.grants(Permission.ROLE_ASSIGN)).toBe(true)
    })
  })
})
