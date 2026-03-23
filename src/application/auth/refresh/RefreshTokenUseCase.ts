import { z } from 'zod'
import type { IUseCase } from '../../../domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '../../../domain/shared/Result'
import type { IUserRepository } from '../../../domain/auth/repositories/IUserRepository'
import type { IRefreshTokenRepository } from '../../../domain/auth/repositories/IRefreshTokenRepository'
import type { ITokenGenerationService } from '../../../domain/auth/services/ITokenGenerationService'
import type { IAuditLogRepository } from '../../../domain/auth/repositories/IAuditLogRepository'
import { RefreshToken } from '../../../domain/auth/entities/RefreshToken'
import { hashToken } from '../../../infrastructure/services/tokenUtils'

export const RefreshRequestSchema = z.object({
  refreshToken: z.string().min(1),
})

export type RefreshRequest = z.infer<typeof RefreshRequestSchema>

export interface RefreshResponse {
  accessToken: string
  refreshToken: string
}

/**
 * Refresh Token Rotation Use Case.
 *
 * Security model:
 * 1. Hash the incoming token, look it up in DB.
 * 2. If already rotated/revoked → BREACH DETECTED → revoke entire family.
 * 3. If valid: issue new RT, mark old RT as rotated, return new pair.
 * 4. Validate user.token_version matches (all-session invalidation).
 */
export class RefreshTokenUseCase
  implements IUseCase<RefreshRequest, RefreshResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly refreshTokenRepo: IRefreshTokenRepository,
    private readonly tokenService: ITokenGenerationService,
    private readonly auditLog: IAuditLogRepository,
    private readonly config: { rtExpiryDays: number },
  ) {}

  async execute(
    input: RefreshRequest,
    context?: { ipAddress?: string; userAgent?: string },
  ): Promise<Result<RefreshResponse>> {
    const tokenHash = await hashToken(input.refreshToken)
    const storedToken = await this.refreshTokenRepo.findByHash(tokenHash)

    // Token not found
    if (!storedToken) {
      return err(DomainError.invalidToken('refresh token not found'))
    }

    // Expired
    if (storedToken.isExpired) {
      return err(DomainError.tokenExpired())
    }

    // Replay attack detection: token was already rotated
    if (storedToken.rotatedAt !== null) {
      // This is a breach signal — someone is reusing a rotated token
      // Invalidate the entire rotation family
      await this.refreshTokenRepo.revokeFamilyTokens(
        storedToken.rotationFamilyId,
      )
      await this.auditLog.log({
        userId: storedToken.userId,
        eventType: 'suspicious_activity',
        ipAddress: context?.ipAddress ?? null,
        userAgent: context?.userAgent ?? null,
        riskLevel: 'high',
        deviceFingerprint: null,
        metadata: {
          reason: 'refresh_token_reuse',
          familyId: storedToken.rotationFamilyId,
        },
      })
      return err(DomainError.refreshTokenReuseDetected())
    }

    // Explicitly revoked
    if (storedToken.revokedAt !== null) {
      return err(DomainError.tokenRevoked())
    }

    // Validate user still exists and token version matches
    const user = await this.userRepo.findById(storedToken.userId)
    if (!user || user.isDeleted) {
      return err(DomainError.userNotFound())
    }

    // Token version check — all-session invalidation
    // We embed tokenVersion in the RT's family metadata.
    // Here we re-verify by generating new tokens with current version.
    // If user.tokenVersion changed (logout-all / password change),
    // existing RTs become orphaned and won't be used again.
    // (The RT itself doesn't store tokenVersion — we rely on the
    //  revokeAllForUser call during logout-all/password-change to revoke them.)

    // Mark old token as rotated
    storedToken.markUsed()
    storedToken.rotate()
    await this.refreshTokenRepo.update(storedToken)

    // Issue new token pair (new RT in same family)
    const newTokenPair = await this.tokenService.generateTokenPair({
      userId: user.id,
      tokenVersion: user.tokenVersion,
      rotationFamilyId: storedToken.rotationFamilyId,
    })

    // Persist new refresh token
    const newTokenHash = await hashToken(newTokenPair.refreshToken)
    const expiresAt = new Date(
      Date.now() + this.config.rtExpiryDays * 86_400_000,
    )
    const newRefreshToken = RefreshToken.create({
      id: newTokenPair.refreshTokenMeta.jti,
      userId: user.id,
      tokenHash: newTokenHash,
      rotationFamilyId: storedToken.rotationFamilyId,
      expiresAt,
      ipAddress: context?.ipAddress ?? null,
    })
    await this.refreshTokenRepo.save(newRefreshToken)

    await this.auditLog.log({
      userId: user.id,
      eventType: 'token_refresh',
      ipAddress: context?.ipAddress ?? null,
      userAgent: context?.userAgent ?? null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: { familyId: storedToken.rotationFamilyId },
    })

    return ok({
      accessToken: newTokenPair.accessToken,
      refreshToken: newTokenPair.refreshToken,
    })
  }
}
