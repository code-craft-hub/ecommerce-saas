import { z } from 'zod'
import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '@/domain/shared/Result'
import { PlaintextPassword } from '@/domain/auth/value-objects/Password'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IRefreshTokenRepository } from '@/domain/auth/repositories/IRefreshTokenRepository'
import type { IPasswordHashingService } from '@/domain/auth/services/IPasswordHashingService'
import type { ISessionCache } from '@/domain/auth/services/ISessionCache'
import type { IEmailService } from '@/domain/auth/services/IEmailService'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'
import type { EventBus } from '@/application/shared/EventBus'

export const ChangePasswordRequestSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: z.string().min(1).max(128),
})

export type ChangePasswordRequest = z.infer<typeof ChangePasswordRequestSchema>

export interface ChangePasswordResponse {
  success: true
}

export class ChangePasswordUseCase
  implements IUseCase<ChangePasswordRequest & { userId: string; currentAccessTokenJti: string; currentAccessTokenExp: number }, ChangePasswordResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly refreshTokenRepo: IRefreshTokenRepository,
    private readonly passwordHasher: IPasswordHashingService,
    private readonly sessionCache: ISessionCache,
    private readonly emailService: IEmailService,
    private readonly auditLog: IAuditLogRepository,
    private readonly eventBus: EventBus,
  ) {}

  async execute(
    input: ChangePasswordRequest & {
      userId: string
      currentAccessTokenJti: string
      currentAccessTokenExp: number
    },
    context?: { ipAddress?: string; userAgent?: string },
  ): Promise<Result<ChangePasswordResponse>> {
    const user = await this.userRepo.findById(input.userId)
    if (!user || user.isDeleted) {
      return err(DomainError.userNotFound())
    }
    if (!user.hasPassword) {
      return err(DomainError.passwordNotSet())
    }

    // Validate current password
    const currentPwResult = PlaintextPassword.create(input.currentPassword)
    if (currentPwResult.isErr()) {
      return err(DomainError.invalidCredentials())
    }

    const isValid = await this.passwordHasher.verify(
      currentPwResult.value,
      user.passwordHash!,
      user.passwordPepperVersion,
    )
    if (!isValid) {
      return err(DomainError.invalidCredentials())
    }

    // Validate new password strength
    const newPwResult = PlaintextPassword.create(input.newPassword)
    if (newPwResult.isErr()) return err(newPwResult.error)

    // Hash and update — changePassword() bumps token_version (invalidates all sessions)
    const { currentPepperVersion } = this.passwordHasher
    const newHash = await this.passwordHasher.hash(
      newPwResult.value,
      currentPepperVersion,
    )
    user.changePassword(newHash, currentPepperVersion)
    await this.userRepo.update(user)

    // Cache the new minimum valid version so the authenticate middleware can
    // reject in-flight access tokens from other sessions immediately, without
    // waiting for the 15-minute natural expiry.
    const atTtlSeconds = Number(process.env.ACCESS_TOKEN_EXPIRY_SECONDS ?? 900)
    await this.sessionCache.setMinTokenVersion(user.id, user.tokenVersion, atTtlSeconds)

    // Revoke all refresh tokens
    await this.refreshTokenRepo.revokeAllForUser(user.id)
    await this.sessionCache.clearUserSessions(user.id)

    // Notify user via email (async, non-blocking)
    this.emailService
      .sendPasswordChangedNotification({
        to: user.email.value,
        name: user.name,
        ipAddress: context?.ipAddress ?? null,
        timestamp: new Date(),
      })
      .catch(() => {})

    await this.auditLog.log({
      userId: user.id,
      eventType: 'password_change',
      ipAddress: context?.ipAddress ?? null,
      userAgent: context?.userAgent ?? null,
      riskLevel: 'medium',
      deviceFingerprint: null,
      metadata: {},
    })

    await this.eventBus.publish(user.domainEvents)
    user.clearDomainEvents()

    return ok({ success: true })
  }
}
