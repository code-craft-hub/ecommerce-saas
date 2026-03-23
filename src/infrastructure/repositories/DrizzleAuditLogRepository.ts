import { eq, desc } from 'drizzle-orm'
import type { DB } from '../persistence/db'
import { auditLog } from '../persistence/schema'
import type {
  IAuditLogRepository,
  AuditLogEntry,
  AuditEventType,
  RiskLevel,
} from '../../domain/auth/repositories/IAuditLogRepository'

export class DrizzleAuditLogRepository implements IAuditLogRepository {
  constructor(private readonly db: DB) {}

  async log(entry: AuditLogEntry): Promise<void> {
    await this.db.insert(auditLog).values({
      userId: entry.userId ?? undefined,
      eventType: entry.eventType as AuditEventType,
      ipAddress: entry.ipAddress ?? undefined,
      userAgent: entry.userAgent ?? undefined,
      riskLevel: entry.riskLevel as RiskLevel,
      deviceFingerprint: entry.deviceFingerprint ?? undefined,
      metadata: entry.metadata,
      createdAt: new Date(),
    })
  }

  async findByUserId(
    userId: string,
    limit = 50,
    offset = 0,
  ): Promise<(AuditLogEntry & { id: string; createdAt: Date })[]> {
    const rows = await this.db
      .select()
      .from(auditLog)
      .where(eq(auditLog.userId, userId))
      .orderBy(desc(auditLog.createdAt))
      .limit(limit)
      .offset(offset)

    return rows.map((row) => ({
      id: row.id,
      userId: row.userId ?? null,
      eventType: row.eventType as AuditEventType,
      ipAddress: row.ipAddress ?? null,
      userAgent: row.userAgent ?? null,
      riskLevel: row.riskLevel as RiskLevel,
      deviceFingerprint: row.deviceFingerprint ?? null,
      metadata: (row.metadata as Record<string, unknown>) ?? {},
      createdAt: row.createdAt,
    }))
  }
}
