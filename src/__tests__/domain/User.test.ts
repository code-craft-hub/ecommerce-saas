import { describe, it, expect } from 'vitest'
import { User } from '../../domain/auth/entities/User'
import { Email } from '../../domain/auth/value-objects/Email'
import { HashedPassword } from '../../domain/auth/value-objects/Password'
import { UserCreatedEvent } from '../../domain/auth/events/UserCreatedEvent'
import { PasswordChangedEvent } from '../../domain/auth/events/PasswordChangedEvent'

function makeEmail(addr = 'test@example.com') {
  const r = Email.create(addr)
  if (r.isErr()) throw new Error('bad email')
  return r.value
}

function makeHash(hash = '$argon2id$dummy') {
  return HashedPassword.fromHash(hash)
}

describe('User Aggregate Root', () => {
  describe('create()', () => {
    it('creates user with correct initial state', () => {
      const user = User.create({
        id: 'user-1',
        email: makeEmail(),
        name: 'Alice',
        passwordHash: makeHash(),
        pepperVersion: 1,
      })

      expect(user.id).toBe('user-1')
      expect(user.email.value).toBe('test@example.com')
      expect(user.emailVerified).toBe(false)
      expect(user.tokenVersion).toBe(1)
      expect(user.isDeleted).toBe(false)
      expect(user.hasPassword).toBe(true)
    })

    it('emits UserCreatedEvent on creation', () => {
      const user = User.create({
        id: 'user-1',
        email: makeEmail(),
        name: 'Alice',
        passwordHash: null,
        pepperVersion: 1,
      })

      expect(user.domainEvents).toHaveLength(1)
      expect(user.domainEvents[0]).toBeInstanceOf(UserCreatedEvent)
    })

    it('supports null passwordHash for OAuth-only users', () => {
      const user = User.create({
        id: 'user-2',
        email: makeEmail('oauth@example.com'),
        name: 'Bob',
        passwordHash: null,
        pepperVersion: 1,
      })
      expect(user.hasPassword).toBe(false)
    })
  })

  describe('verifyEmail()', () => {
    it('marks email as verified', () => {
      const user = User.create({
        id: 'u1',
        email: makeEmail(),
        name: 'Alice',
        passwordHash: null,
        pepperVersion: 1,
      })
      expect(user.emailVerified).toBe(false)
      user.verifyEmail()
      expect(user.emailVerified).toBe(true)
    })
  })

  describe('changePassword()', () => {
    it('increments token version (invalidates all sessions)', () => {
      const user = User.create({
        id: 'u1',
        email: makeEmail(),
        name: 'Alice',
        passwordHash: makeHash(),
        pepperVersion: 1,
      })
      const initialVersion = user.tokenVersion

      user.changePassword(makeHash('new-hash'), 1)

      expect(user.tokenVersion).toBe(initialVersion + 1)
    })

    it('emits PasswordChangedEvent with allSessionsInvalidated=true', () => {
      const user = User.create({
        id: 'u1',
        email: makeEmail(),
        name: 'Alice',
        passwordHash: makeHash(),
        pepperVersion: 1,
      })
      user.clearDomainEvents()

      user.changePassword(makeHash('new-hash'), 1)

      const events = user.domainEvents
      expect(events).toHaveLength(1)
      const event = events[0] as PasswordChangedEvent
      expect(event).toBeInstanceOf(PasswordChangedEvent)
      expect(event.allSessionsInvalidated).toBe(true)
    })
  })

  describe('setPassword()', () => {
    it('does NOT increment token version (initial set)', () => {
      const user = User.create({
        id: 'u1',
        email: makeEmail(),
        name: 'Alice',
        passwordHash: null,
        pepperVersion: 1,
      })
      const version = user.tokenVersion
      user.clearDomainEvents()

      user.setPassword(makeHash('new-hash'), 1)

      expect(user.tokenVersion).toBe(version)
    })

    it('emits PasswordChangedEvent with allSessionsInvalidated=false', () => {
      const user = User.create({
        id: 'u1',
        email: makeEmail(),
        name: 'Alice',
        passwordHash: null,
        pepperVersion: 1,
      })
      user.clearDomainEvents()
      user.setPassword(makeHash('new-hash'), 1)

      const event = user.domainEvents[0] as PasswordChangedEvent
      expect(event.allSessionsInvalidated).toBe(false)
    })
  })

  describe('revokeAllSessions()', () => {
    it('increments token version', () => {
      const user = User.create({
        id: 'u1',
        email: makeEmail(),
        name: 'Alice',
        passwordHash: null,
        pepperVersion: 1,
      })
      const v = user.tokenVersion
      user.revokeAllSessions()
      expect(user.tokenVersion).toBe(v + 1)
    })

    it('can be called multiple times (each bump)', () => {
      const user = User.create({
        id: 'u1',
        email: makeEmail(),
        name: 'Alice',
        passwordHash: null,
        pepperVersion: 1,
      })
      const v = user.tokenVersion
      user.revokeAllSessions()
      user.revokeAllSessions()
      expect(user.tokenVersion).toBe(v + 2)
    })
  })

  describe('softDelete()', () => {
    it('sets deletedAt and isDeleted', () => {
      const user = User.create({
        id: 'u1',
        email: makeEmail(),
        name: 'Alice',
        passwordHash: null,
        pepperVersion: 1,
      })
      expect(user.isDeleted).toBe(false)
      user.softDelete()
      expect(user.isDeleted).toBe(true)
      expect(user.deletedAt).toBeInstanceOf(Date)
    })
  })

  describe('domain events', () => {
    it('clearDomainEvents() removes all events', () => {
      const user = User.create({
        id: 'u1',
        email: makeEmail(),
        name: 'Alice',
        passwordHash: null,
        pepperVersion: 1,
      })
      expect(user.domainEvents).toHaveLength(1)
      user.clearDomainEvents()
      expect(user.domainEvents).toHaveLength(0)
    })
  })
})
