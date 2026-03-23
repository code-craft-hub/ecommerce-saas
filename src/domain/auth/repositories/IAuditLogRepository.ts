export type AuditEventType =
  | 'signup'
  | 'login'
  | 'logout'
  | 'logout_all'
  | 'password_change'
  | 'password_reset_requested'
  | 'password_reset_completed'
  | 'email_verified'
  | 'oauth_link'
  | 'oauth_unlink'
  | 'session_revoked'
  | 'token_refresh'
  | 'failed_login'
  | 'account_locked'
  | 'suspicious_activity'

export type RiskLevel = 'low' | 'medium' | 'high'

export interface AuditLogEntry {
  userId: string | null
  eventType: AuditEventType
  ipAddress: string | null
  userAgent: string | null
  riskLevel: RiskLevel
  deviceFingerprint: string | null
  metadata: Record<string, unknown>
}

export interface IAuditLogRepository {
  /** Append-only — never update or delete */
  log(entry: AuditLogEntry): Promise<void>
  findByUserId(
    userId: string,
    limit?: number,
    offset?: number,
  ): Promise<
    (AuditLogEntry & { id: string; createdAt: Date })[]
  >
}
