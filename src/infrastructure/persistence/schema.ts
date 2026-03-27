import {
  pgTable,
  uuid,
  varchar,
  boolean,
  integer,
  timestamp,
  jsonb,
  pgEnum,
  index,
  uniqueIndex,
  text,
} from 'drizzle-orm/pg-core'
import { relations } from 'drizzle-orm'

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export const oauthProviderEnum = pgEnum('oauth_provider', [
  'google',
  'github',
  'microsoft',
])

export const auditEventTypeEnum = pgEnum('audit_event_type', [
  'signup',
  'login',
  'logout',
  'logout_all',
  'password_change',
  'password_reset_requested',
  'password_reset_completed',
  'email_verified',
  'oauth_link',
  'oauth_unlink',
  'session_revoked',
  'token_refresh',
  'failed_login',
  'account_locked',
  'suspicious_activity',
])

export const riskLevelEnum = pgEnum('risk_level', ['low', 'medium', 'high'])

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/**
 * Core user record.
 * No auth-specific fields beyond password_hash — keep it normalized.
 */
export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: varchar('email', { length: 254 }).notNull().unique(),
    emailVerified: boolean('email_verified').notNull().default(false),
    name: varchar('name', { length: 100 }).notNull(),
    /** Argon2id hash — null for OAuth-only accounts */
    passwordHash: text('password_hash'),
    /** Which pepper was used — allows pepper rotation */
    passwordPepperVersion: integer('password_pepper_version')
      .notNull()
      .default(1),
    /**
     * Token version for all-session revocation.
     * Increment → all JWTs with lower version become invalid.
     */
    tokenVersion: integer('token_version').notNull().default(1),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    /** Soft delete — never hard-delete users */
    deletedAt: timestamp('deleted_at', { withTimezone: true }),
    /** Custom claims, preferences — extensible */
    metadata: jsonb('metadata').notNull().default({}),
  },
  (t) => [
    index('users_email_idx').on(t.email),
    index('users_deleted_at_idx').on(t.deletedAt),
  ],
)

/**
 * Rotation families track the lineage of refresh token chains.
 * When a reuse is detected, the entire family is invalidated.
 */
export const rotationFamilies = pgTable('rotation_families', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true })
    .notNull()
    .defaultNow(),
  /** Set when a family is compromised — breach signal */
  compromisedAt: timestamp('compromised_at', { withTimezone: true }),
})

/**
 * Refresh tokens — opaque tokens with rotation tracking.
 * Store SHA-256 hash only — never plaintext.
 */
export const refreshTokens = pgTable(
  'refresh_tokens',
  {
    id: uuid('id').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    /** SHA-256(raw_token) — index for fast lookup */
    tokenHash: varchar('token_hash', { length: 64 }).notNull(),
    rotationFamilyId: uuid('rotation_family_id')
      .notNull()
      .references(() => rotationFamilies.id, { onDelete: 'cascade' }),
    issuedAt: timestamp('issued_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    /** Set when this token was replaced by a new one (normal rotation) */
    rotatedAt: timestamp('rotated_at', { withTimezone: true }),
    /** Set when explicitly revoked (logout, password change) */
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    /** Last time this token was successfully used */
    usedAt: timestamp('used_at', { withTimezone: true }),
    deviceId: varchar('device_id', { length: 255 }),
    ipAddress: varchar('ip_address', { length: 45 }),
    /** SHA-256(user_agent) — detect device switches */
    userAgentHash: varchar('user_agent_hash', { length: 64 }),
    /** Raw user agent string (truncated to 512 chars) — for session list display */
    userAgent: varchar('user_agent', { length: 512 }),
  },
  (t) => [
    uniqueIndex('refresh_tokens_hash_idx').on(t.tokenHash),
    index('refresh_tokens_user_id_idx').on(t.userId),
    index('refresh_tokens_family_idx').on(t.rotationFamilyId),
    index('refresh_tokens_expires_idx').on(t.expiresAt),
  ],
)

/**
 * Linked OAuth accounts — one user can have multiple providers.
 */
export const oauthAccounts = pgTable(
  'oauth_accounts',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    provider: oauthProviderEnum('provider').notNull(),
    providerUserId: varchar('provider_user_id', { length: 255 }).notNull(),
    email: varchar('email', { length: 254 }).notNull(),
    name: varchar('name', { length: 100 }).notNull(),
    pictureUrl: text('picture_url'),
    /** Raw claims from provider (scopes, verified_email, etc.) */
    providerMetadata: jsonb('provider_metadata').notNull().default({}),
    linkedAt: timestamp('linked_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('oauth_accounts_provider_user_idx').on(
      t.provider,
      t.providerUserId,
    ),
    index('oauth_accounts_user_id_idx').on(t.userId),
  ],
)

/**
 * Immutable audit log — append-only, no updates or deletes.
 * Indexed for efficient user-history queries.
 */
export const auditLog = pgTable(
  'audit_log',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id').references(() => users.id, {
      onDelete: 'set null',
    }),
    eventType: auditEventTypeEnum('event_type').notNull(),
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: text('user_agent'),
    riskLevel: riskLevelEnum('risk_level').notNull().default('low'),
    deviceFingerprint: varchar('device_fingerprint', { length: 255 }),
    metadata: jsonb('metadata').notNull().default({}),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    index('audit_log_user_id_created_idx').on(t.userId, t.createdAt),
    index('audit_log_event_type_idx').on(t.eventType),
    index('audit_log_risk_level_idx').on(t.riskLevel),
  ],
)

// ---------------------------------------------------------------------------
// Authorization tables
// ---------------------------------------------------------------------------

/**
 * Roles — named permission bundles for RBAC.
 * System roles (user, admin, moderator, service) are seeded at startup.
 */
export const roles = pgTable(
  'roles',
  {
    name: varchar('name', { length: 64 }).primaryKey(),
    displayName: varchar('display_name', { length: 100 }).notNull(),
    description: text('description').notNull().default(''),
    /** JSON array of permission strings, e.g. ["user:read:self","session:revoke:self"] */
    permissions: jsonb('permissions').notNull().default([]),
    /** System roles cannot be deleted */
    isSystem: boolean('is_system').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
)

/**
 * User ↔ Role assignment table (RBAC subject assignments).
 * Supports optional resource-scoped assignments for multi-tenancy.
 */
export const userRoles = pgTable(
  'user_roles',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    roleName: varchar('role_name', { length: 64 })
      .notNull()
      .references(() => roles.name, { onDelete: 'cascade' }),
    assignedBy: uuid('assigned_by').references(() => users.id, {
      onDelete: 'set null',
    }),
    /** Scope to a specific resource (e.g. tenant, org) — null = global */
    resourceId: varchar('resource_id', { length: 255 }),
    resourceType: varchar('resource_type', { length: 64 }),
    assignedAt: timestamp('assigned_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    uniqueIndex('user_roles_user_role_idx').on(t.userId, t.roleName, t.resourceId),
    index('user_roles_user_id_idx').on(t.userId),
    index('user_roles_role_name_idx').on(t.roleName),
  ],
)

/**
 * Resource relations for ReBAC (Relationship-Based Access Control).
 * Stores (subject, relation, object) tuples.
 * Examples:
 *   user:alice  owns   post:123
 *   user:alice  member org:acme
 */
export const relationTypeEnum = pgEnum('relation_type', [
  'owner',
  'member',
  'editor',
  'viewer',
  'admin',
])

export const resourceRelations = pgTable(
  'resource_relations',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    subjectType: varchar('subject_type', { length: 64 }).notNull().default('user'),
    subjectId: uuid('subject_id').notNull(),
    relation: relationTypeEnum('relation').notNull(),
    objectType: varchar('object_type', { length: 64 }).notNull(),
    objectId: varchar('object_id', { length: 255 }).notNull(),
    createdBy: uuid('created_by').references(() => users.id, {
      onDelete: 'set null',
    }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    uniqueIndex('resource_relations_tuple_idx').on(
      t.subjectId,
      t.relation,
      t.objectType,
      t.objectId,
    ),
    index('resource_relations_subject_idx').on(t.subjectId, t.objectType),
    index('resource_relations_object_idx').on(t.objectType, t.objectId),
  ],
)

// ---------------------------------------------------------------------------
// Relations (for Drizzle query API)
// ---------------------------------------------------------------------------

export const usersRelations = relations(users, ({ many }) => ({
  refreshTokens: many(refreshTokens),
  oauthAccounts: many(oauthAccounts),
  auditLogs: many(auditLog),
  rotationFamilies: many(rotationFamilies),
}))

export const refreshTokensRelations = relations(refreshTokens, ({ one }) => ({
  user: one(users, { fields: [refreshTokens.userId], references: [users.id] }),
  rotationFamily: one(rotationFamilies, {
    fields: [refreshTokens.rotationFamilyId],
    references: [rotationFamilies.id],
  }),
}))

export const oauthAccountsRelations = relations(oauthAccounts, ({ one }) => ({
  user: one(users, { fields: [oauthAccounts.userId], references: [users.id] }),
}))

export const auditLogRelations = relations(auditLog, ({ one }) => ({
  user: one(users, { fields: [auditLog.userId], references: [users.id] }),
}))

export const userRolesRelations = relations(userRoles, ({ one }) => ({
  user: one(users, { fields: [userRoles.userId], references: [users.id] }),
  role: one(roles, { fields: [userRoles.roleName], references: [roles.name] }),
}))

export const rolesRelations = relations(roles, ({ many }) => ({
  userRoles: many(userRoles),
}))
