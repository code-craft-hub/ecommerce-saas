import type { IUseCase } from '../../../domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '../../../domain/shared/Result'
import type { IRefreshTokenRepository } from '../../../domain/auth/repositories/IRefreshTokenRepository'
import type { ISessionCache } from '../../../domain/auth/services/ISessionCache'
import type { IAuditLogRepository } from '../../../domain/auth/repositories/IAuditLogRepository'
import type { EventBus } from '../../shared/EventBus'
import { SessionRevokedEvent } from '../../../domain/auth/events/SessionRevokedEvent'

export interface RevokeSessionRequest {
  userId: string
  sessionId: string
}

export interface RevokeSessionResponse {
  success: true
}

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

    token.revoke()
    await this.refreshTokenRepo.update(token)

    await this.auditLog.log({
      userId: input.userId,
      eventType: 'session_revoked',
      ipAddress: context?.ipAddress ?? null,
      userAgent: null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: { sessionId: input.sessionId },
    })

    await this.eventBus.publishOne(
      new SessionRevokedEvent(input.userId, 1, false),
    )

    return ok({ success: true })
  }
}
