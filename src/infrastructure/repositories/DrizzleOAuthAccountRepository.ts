import { eq, and } from 'drizzle-orm'
import type { DB } from '../persistence/db'
import { oauthAccounts } from '../persistence/schema'
import type { IOAuthAccountRepository } from '../../domain/auth/repositories/IOAuthAccountRepository'
import { OAuthAccount } from '../../domain/auth/entities/OAuthAccount'
import type { OAuthProvider } from '../../domain/auth/value-objects/OAuthProfile'

type OAuthAccountRow = typeof oauthAccounts.$inferSelect

function toDomain(row: OAuthAccountRow): OAuthAccount {
  return OAuthAccount.reconstitute({
    id: row.id,
    userId: row.userId,
    provider: row.provider as OAuthProvider,
    providerUserId: row.providerUserId,
    email: row.email,
    name: row.name,
    pictureUrl: row.pictureUrl ?? null,
    providerMetadata: (row.providerMetadata as Record<string, unknown>) ?? {},
    linkedAt: row.linkedAt,
    lastLoginAt: row.lastLoginAt ?? null,
  })
}

export class DrizzleOAuthAccountRepository
  implements IOAuthAccountRepository
{
  constructor(private readonly db: DB) {}

  async findByProvider(
    provider: OAuthProvider,
    providerUserId: string,
  ): Promise<OAuthAccount | null> {
    const rows = await this.db
      .select()
      .from(oauthAccounts)
      .where(
        and(
          eq(oauthAccounts.provider, provider),
          eq(oauthAccounts.providerUserId, providerUserId),
        ),
      )
      .limit(1)

    return rows[0] ? toDomain(rows[0]) : null
  }

  async findByUserId(userId: string): Promise<OAuthAccount[]> {
    const rows = await this.db
      .select()
      .from(oauthAccounts)
      .where(eq(oauthAccounts.userId, userId))

    return rows.map(toDomain)
  }

  async save(account: OAuthAccount): Promise<void> {
    await this.db.insert(oauthAccounts).values({
      id: account.id,
      userId: account.userId,
      provider: account.provider,
      providerUserId: account.providerUserId,
      email: account.email,
      name: account.name,
      pictureUrl: account.pictureUrl ?? undefined,
      providerMetadata: account.providerMetadata,
      linkedAt: account.linkedAt,
      lastLoginAt: account.lastLoginAt ?? undefined,
    })
  }

  async update(account: OAuthAccount): Promise<void> {
    await this.db
      .update(oauthAccounts)
      .set({
        email: account.email,
        name: account.name,
        pictureUrl: account.pictureUrl ?? undefined,
        providerMetadata: account.providerMetadata,
        lastLoginAt: account.lastLoginAt ?? undefined,
      })
      .where(eq(oauthAccounts.id, account.id))
  }

  async delete(id: string): Promise<void> {
    await this.db.delete(oauthAccounts).where(eq(oauthAccounts.id, id))
  }
}
