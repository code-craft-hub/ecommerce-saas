import type { IUseCase } from '../../../domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '../../../domain/shared/Result'
import type { IUserRepository } from '../../../domain/auth/repositories/IUserRepository'
import type { IRefreshTokenRepository } from '../../../domain/auth/repositories/IRefreshTokenRepository'
import type { ISessionCache } from '../../../domain/auth/services/ISessionCache'
import type { IAuditLogRepository } from '../../../domain/auth/repositories/IAuditLogRepository'
import type { EventBus } from '../../shared/EventBus'
import { SessionRevokedEvent } from '../../../domain/auth/events/SessionRevokedEvent'

export interface LogoutAllRequest {
  userId: string
  currentAccessTokenJti: string
  currentAccessTokenExp: number
}

export interface LogoutAllResponse {
  success: true
  sessionsRevoked: number
}

export class LogoutAllUseCase
  implements IUseCase<LogoutAllRequest, LogoutAllResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly refreshTokenRepo: IRefreshTokenRepository,
    private readonly sessionCache: ISessionCache,
    private readonly auditLog: IAuditLogRepository,
    private readonly eventBus: EventBus,
  ) {}

  async execute(
    input: LogoutAllRequest,
    context?: { ipAddress?: string; userAgent?: string },
  ): Promise<Result<LogoutAllResponse>> {
    const user = await this.userRepo.findById(input.userId)
    if (!user || user.isDeleted) {
      return err(DomainError.userNotFound())
    }

    // Count before revocation for response metadata
    const activeSessions = await this.refreshTokenRepo.countActiveForUser(
      input.userId,
    )

    // 1. Increment token_version — INSTANTLY invalidates ALL JWTs in flight
    user.revokeAllSessions()
    await this.userRepo.update(user)

    // 2. Revoke all refresh tokens in DB
    await this.refreshTokenRepo.revokeAllForUser(input.userId)

    // 3. Clear Redis session cache for user
    await this.sessionCache.clearUserSessions(input.userId)

    // 4. Denylist current access token too (defense-in-depth)
    const remainingTtl = Math.max(
      0,
      Math.floor(input.currentAccessTokenExp - Date.now() / 1000),
    )
    if (remainingTtl > 0) {
      await this.sessionCache.denylistToken(
        input.currentAccessTokenJti,
        remainingTtl,
      )
    }

    await this.auditLog.log({
      userId: input.userId,
      eventType: 'logout_all',
      ipAddress: context?.ipAddress ?? null,
      userAgent: context?.userAgent ?? null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: { sessionsRevoked: activeSessions },
    })

    await this.eventBus.publishOne(
      new SessionRevokedEvent(input.userId, activeSessions, true),
    )

    return ok({ success: true, sessionsRevoked: activeSessions })
  }
}
