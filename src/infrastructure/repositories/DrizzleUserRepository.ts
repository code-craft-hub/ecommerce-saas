import { eq, isNull } from 'drizzle-orm'
import type { DB } from '@/infrastructure/persistence/db'
import { users } from '@/infrastructure/persistence/schema'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import { User } from '@/domain/auth/entities/User'
import { Email } from '@/domain/auth/value-objects/Email'
import { HashedPassword } from '@/domain/auth/value-objects/Password'

type UserRow = typeof users.$inferSelect

function toDomain(row: UserRow): User {
  const emailResult = Email.create(row.email)
  if (emailResult.isErr()) {
    throw new Error(`Invalid email in DB: ${row.email}`)
  }

  return User.reconstitute({
    id: row.id,
    email: emailResult.value,
    emailVerified: row.emailVerified,
    name: row.name,
    passwordHash: row.passwordHash
      ? HashedPassword.fromHash(row.passwordHash)
      : null,
    passwordPepperVersion: row.passwordPepperVersion,
    tokenVersion: row.tokenVersion,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    deletedAt: row.deletedAt ?? null,
    metadata: (row.metadata as Record<string, unknown>) ?? {},
  })
}

function toRow(user: User): Omit<UserRow, 'id'> & { id: string } {
  return {
    id: user.id,
    email: user.email.value,
    emailVerified: user.emailVerified,
    name: user.name,
    passwordHash: user.passwordHash?.hash ?? null,
    passwordPepperVersion: user.passwordPepperVersion,
    tokenVersion: user.tokenVersion,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    deletedAt: user.deletedAt,
    metadata: user.metadata,
  }
}

export class DrizzleUserRepository implements IUserRepository {
  constructor(private readonly db: DB) {}

  async findById(id: string): Promise<User | null> {
    const rows = await this.db
      .select()
      .from(users)
      .where(eq(users.id, id))
      .limit(1)

    return rows[0] ? toDomain(rows[0]) : null
  }

  async findByEmail(email: string): Promise<User | null> {
    const rows = await this.db
      .select()
      .from(users)
      .where(eq(users.email, email.toLowerCase().trim()))
      .limit(1)

    return rows[0] ? toDomain(rows[0]) : null
  }

  async save(user: User): Promise<void> {
    await this.db.insert(users).values(toRow(user))
  }

  async update(user: User): Promise<void> {
    const row = toRow(user)
    await this.db
      .update(users)
      .set({
        emailVerified: row.emailVerified,
        name: row.name,
        passwordHash: row.passwordHash,
        passwordPepperVersion: row.passwordPepperVersion,
        tokenVersion: row.tokenVersion,
        updatedAt: new Date(),
        deletedAt: row.deletedAt,
        metadata: row.metadata,
      })
      .where(eq(users.id, user.id))
  }

  async delete(id: string): Promise<void> {
    await this.db
      .update(users)
      .set({ deletedAt: new Date(), updatedAt: new Date() })
      .where(eq(users.id, id))
  }
}
