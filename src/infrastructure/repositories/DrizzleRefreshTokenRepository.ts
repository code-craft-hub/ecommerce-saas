import { eq, and, isNull, lt, gt, count } from 'drizzle-orm'
import type { DB } from '@/infrastructure/persistence/db'
import { refreshTokens, rotationFamilies } from '@/infrastructure/persistence/schema'
import type { IRefreshTokenRepository } from '@/domain/auth/repositories/IRefreshTokenRepository'
import { RefreshToken } from '@/domain/auth/entities/RefreshToken'

type RefreshTokenRow = typeof refreshTokens.$inferSelect

function toDomain(row: RefreshTokenRow): RefreshToken {
  return RefreshToken.reconstitute({
    id: row.id,
    userId: row.userId,
    tokenHash: row.tokenHash,
    rotationFamilyId: row.rotationFamilyId,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt ?? null,
    rotatedAt: row.rotatedAt ?? null,
    usedAt: row.usedAt ?? null,
    deviceId: row.deviceId ?? null,
    ipAddress: row.ipAddress ?? null,
    userAgentHash: row.userAgentHash ?? null,
    userAgent: row.userAgent ?? null,
  })
}

export class DrizzleRefreshTokenRepository
  implements IRefreshTokenRepository
{
  constructor(private readonly db: DB) {}

  async findByHash(tokenHash: string): Promise<RefreshToken | null> {
    const rows = await this.db
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.tokenHash, tokenHash))
      .limit(1)

    return rows[0] ? toDomain(rows[0]) : null
  }

  async findById(id: string): Promise<RefreshToken | null> {
    const rows = await this.db
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.id, id))
      .limit(1)

    return rows[0] ? toDomain(rows[0]) : null
  }

  async findActiveByUserId(userId: string): Promise<RefreshToken[]> {
    const now = new Date()
    const rows = await this.db
      .select()
      .from(refreshTokens)
      .where(
        and(
          eq(refreshTokens.userId, userId),
          isNull(refreshTokens.revokedAt),
          isNull(refreshTokens.rotatedAt),
        ),
      )

    // Filter expired in application (avoids raw SQL date comparison quirks)
    return rows
      .map(toDomain)
      .filter((t) => t.expiresAt > now)
  }

  async save(token: RefreshToken): Promise<void> {
    // Ensure rotation family exists
    await this.db
      .insert(rotationFamilies)
      .values({
        id: token.rotationFamilyId,
        userId: token.userId,
        createdAt: new Date(),
      })
      .onConflictDoNothing()

    await this.db.insert(refreshTokens).values({
      id: token.id,
      userId: token.userId,
      tokenHash: token.tokenHash,
      rotationFamilyId: token.rotationFamilyId,
      issuedAt: token.issuedAt,
      expiresAt: token.expiresAt,
      revokedAt: token.revokedAt ?? undefined,
      rotatedAt: token.rotatedAt ?? undefined,
      usedAt: token.usedAt ?? undefined,
      deviceId: token.deviceId ?? undefined,
      ipAddress: token.ipAddress ?? undefined,
      userAgentHash: token.userAgentHash ?? undefined,
      userAgent: token.userAgent ?? undefined,
    })
  }

  async update(token: RefreshToken): Promise<void> {
    await this.db
      .update(refreshTokens)
      .set({
        revokedAt: token.revokedAt ?? undefined,
        rotatedAt: token.rotatedAt ?? undefined,
        usedAt: token.usedAt ?? undefined,
      })
      .where(eq(refreshTokens.id, token.id))
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const now = new Date()
    const result = await this.db
      .update(refreshTokens)
      .set({ revokedAt: now })
      .where(
        and(
          eq(refreshTokens.userId, userId),
          isNull(refreshTokens.revokedAt),
        ),
      )
    return result.length
  }

  async revokeFamilyTokens(familyId: string): Promise<void> {
    const now = new Date()
    await this.db
      .update(refreshTokens)
      .set({ revokedAt: now })
      .where(
        and(
          eq(refreshTokens.rotationFamilyId, familyId),
          isNull(refreshTokens.revokedAt),
        ),
      )
    // Mark family as compromised
    await this.db
      .update(rotationFamilies)
      .set({ compromisedAt: now })
      .where(eq(rotationFamilies.id, familyId))
  }

  async countActiveForUser(userId: string): Promise<number> {
    const now = new Date()
    const rows = await this.db
      .select({ count: count() })
      .from(refreshTokens)
      .where(
        and(
          eq(refreshTokens.userId, userId),
          isNull(refreshTokens.revokedAt),
          isNull(refreshTokens.rotatedAt),
          gt(refreshTokens.expiresAt, now),
        ),
      )
    return Number(rows[0]?.count ?? 0)
  }

  async deleteExpired(): Promise<number> {
    const now = new Date()
    const result = await this.db
      .delete(refreshTokens)
      .where(lt(refreshTokens.expiresAt, now))
    return result.length
  }
}
