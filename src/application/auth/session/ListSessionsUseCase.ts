import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, ok } from '@/domain/shared/Result'
import type { IRefreshTokenRepository } from '@/domain/auth/repositories/IRefreshTokenRepository'
import { parseDevice } from '@/infrastructure/services/DeviceParser'

export interface ListSessionsRequest {
  userId: string
  currentSessionId: string | null
}

export interface SessionDTO {
  id: string
  deviceId: string | null
  ipAddress: string | null
  /** Human-readable device label e.g. "Chrome on Windows" */
  deviceLabel: string
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown'
  createdAt: Date
  lastUsedAt: Date | null
  expiresAt: Date
  isCurrent: boolean
}

export class ListSessionsUseCase
  implements IUseCase<ListSessionsRequest, SessionDTO[]>
{
  constructor(private readonly refreshTokenRepo: IRefreshTokenRepository) {}

  async execute(
    input: ListSessionsRequest,
  ): Promise<Result<SessionDTO[]>> {
    const tokens = await this.refreshTokenRepo.findActiveByUserId(input.userId)

    const sessions: SessionDTO[] = tokens.map((t) => {
      const device = parseDevice(t.userAgent)
      return {
        id: t.id,
        deviceId: t.deviceId,
        ipAddress: t.ipAddress,
        deviceLabel: device.label,
        deviceType: device.deviceType,
        createdAt: t.issuedAt,
        lastUsedAt: t.usedAt,
        expiresAt: t.expiresAt,
        isCurrent: t.id === input.currentSessionId,
      }
    })

    return ok(sessions)
  }
}
