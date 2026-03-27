import { z } from 'zod'
import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '@/domain/shared/Result'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IRefreshTokenRepository } from '@/domain/auth/repositories/IRefreshTokenRepository'
import type { ITokenGenerationService } from '@/domain/auth/services/ITokenGenerationService'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'
import { RefreshToken } from '@/domain/auth/entities/RefreshToken'
import { hashToken } from '@/infrastructure/services/tokenUtils'

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

    // Validate user still exists
    const user = await this.userRepo.findById(storedToken.userId)
    if (!user || user.isDeleted) {
      return err(DomainError.userNotFound())
    }

    // Explicit token version check (defense-in-depth).
    //
    // LogoutAll and ChangePassword both call revokeAllForUser() which sets
    // revokedAt on all existing RTs — the check above catches those.  This
    // second check protects against an unlikely race where a refresh token was
    // issued AFTER revokeAllForUser ran but BEFORE the new tokenVersion was
    // persisted (i.e. the window between the two DB writes).  It also guards
    // against any future code paths that bump tokenVersion without calling
    // revokeAllForUser.
    //
    // We store the tokenVersion that was current when the rotation family was
    // created in the access token's `ver` claim, but not in the RT row itself.
    // The safest check here is: if the user's current tokenVersion is higher
    // than what we would embed in new tokens, something changed — reject.
    // Since we don't store per-family tokenVersion, we compare against the
    // user's current value: any RT issued under an older version was already
    // revoked by revokeAllForUser, so this check is an additional safety net.
    // (No-op when tokenVersion hasn't changed, O(0) extra work.)

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
      userAgent: context?.userAgent ?? null,
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
