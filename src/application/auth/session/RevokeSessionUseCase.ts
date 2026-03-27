import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '@/domain/shared/Result'
import type { IRefreshTokenRepository } from '@/domain/auth/repositories/IRefreshTokenRepository'
import type { ISessionCache } from '@/domain/auth/services/ISessionCache'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'
import type { EventBus } from '@/application/shared/EventBus'
import { SessionRevokedEvent } from '@/domain/auth/events/SessionRevokedEvent'

export interface RevokeSessionRequest {
  userId: string
  sessionId: string
  /** Remaining TTL of the current access token (seconds) — used to bound the denylist entry */
  accessTokenTtlSeconds?: number
}

export interface RevokeSessionResponse {
  success: true
}

/** Default access token TTL if not provided — matches the 15 min default */
const DEFAULT_AT_TTL_SECONDS = 900

export class RevokeSessionUseCase
  implements IUseCase<RevokeSessionRequest, RevokeSessionResponse>
{
  constructor(
    private readonly refreshTokenRepo: IRefreshTokenRepository,
    private readonly sessionCache: ISessionCache,
    private readonly auditLog: IAuditLogRepository,
    private readonly eventBus: EventBus,
  ) {}

  async execute(
    input: RevokeSessionRequest,
    context?: { ipAddress?: string },
  ): Promise<Result<RevokeSessionResponse>> {
    const token = await this.refreshTokenRepo.findById(input.sessionId)

    if (!token) {
      return err(DomainError.invalidToken('session not found'))
    }

    // Authorization check — users can only revoke their own sessions
    if (token.userId !== input.userId) {
      return err(DomainError.forbidden())
    }

    // Revoke the refresh token in DB
    token.revoke()
    await this.refreshTokenRepo.update(token)

    // Mark the rotation family as revoked in Redis so that any access tokens
    // that were issued in this session (sid = rotationFamilyId) are rejected
    // immediately by the authenticate middleware, without waiting for expiry.
    const ttl = input.accessTokenTtlSeconds ?? DEFAULT_AT_TTL_SECONDS
    await this.sessionCache.revokeSession(token.rotationFamilyId, ttl)

    await this.auditLog.log({
      userId: input.userId,
      eventType: 'session_revoked',
      ipAddress: context?.ipAddress ?? null,
      userAgent: null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: { sessionId: input.sessionId, familyId: token.rotationFamilyId },
    })

    await this.eventBus.publishOne(
      new SessionRevokedEvent(input.userId, 1, false),
    )

    return ok({ success: true })
  }
}
