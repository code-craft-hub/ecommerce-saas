import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, ok } from '@/domain/shared/Result'
import type { IRefreshTokenRepository } from '@/domain/auth/repositories/IRefreshTokenRepository'
import type { ISessionCache } from '@/domain/auth/services/ISessionCache'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'
import { hashToken } from '@/infrastructure/services/tokenUtils'

export interface LogoutRequest {
  userId: string
  accessTokenJti: string
  accessTokenExp: number
  refreshToken: string | null
}

export interface LogoutResponse {
  success: true
}

export class LogoutUseCase
  implements IUseCase<LogoutRequest, LogoutResponse>
{
  constructor(
    private readonly refreshTokenRepo: IRefreshTokenRepository,
    private readonly sessionCache: ISessionCache,
    private readonly auditLog: IAuditLogRepository,
  ) {}

  async execute(
    input: LogoutRequest,
    context?: { ipAddress?: string; userAgent?: string },
  ): Promise<Result<LogoutResponse>> {
    // 1. Add access token JTI to Redis denylist
    const remainingTtl = Math.max(
      0,
      Math.floor(input.accessTokenExp - Date.now() / 1000),
    )
    if (remainingTtl > 0) {
      await this.sessionCache.denylistToken(input.accessTokenJti, remainingTtl)
    }

    // 2. Revoke current refresh token
    if (input.refreshToken) {
      const tokenHash = await hashToken(input.refreshToken)
      const stored = await this.refreshTokenRepo.findByHash(tokenHash)
      if (stored && stored.isValid) {
        stored.revoke()
        await this.refreshTokenRepo.update(stored)
      }
    }

    await this.auditLog.log({
      userId: input.userId,
      eventType: 'logout',
      ipAddress: context?.ipAddress ?? null,
      userAgent: context?.userAgent ?? null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: {},
    })

    return ok({ success: true })
  }
}
