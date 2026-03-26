import { z } from 'zod'
import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '@/domain/shared/Result'
import { PlaintextPassword } from '@/domain/auth/value-objects/Password'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IRefreshTokenRepository } from '@/domain/auth/repositories/IRefreshTokenRepository'
import type { IPasswordHashingService } from '@/domain/auth/services/IPasswordHashingService'
import type { ITokenGenerationService } from '@/domain/auth/services/ITokenGenerationService'
import type { ISessionCache } from '@/domain/auth/services/ISessionCache'
import type { IEmailService } from '@/domain/auth/services/IEmailService'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'
import type { EventBus } from '@/application/shared/EventBus'

export const ResetPasswordRequestSchema = z.object({
  token: z.string().min(1),
  newPassword: z.string().min(1).max(128),
})

export type ResetPasswordRequest = z.infer<typeof ResetPasswordRequestSchema>

export interface ResetPasswordResponse {
  success: true
}

export class ResetPasswordUseCase
  implements IUseCase<ResetPasswordRequest, ResetPasswordResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly refreshTokenRepo: IRefreshTokenRepository,
    private readonly passwordHasher: IPasswordHashingService,
    private readonly tokenService: ITokenGenerationService,
    private readonly sessionCache: ISessionCache,
    private readonly emailService: IEmailService,
    private readonly auditLog: IAuditLogRepository,
    private readonly eventBus: EventBus,
  ) {}

  async execute(
    input: ResetPasswordRequest,
    context?: { ipAddress?: string },
  ): Promise<Result<ResetPasswordResponse>> {
    // Verify reset token
    let payload: { userId: string; email: string; purpose: string }
    try {
      payload = await this.tokenService.verifyVerificationToken(input.token)
    } catch {
      return err(DomainError.invalidToken('reset token invalid or expired'))
    }

    if (payload.purpose !== 'password_reset') {
      return err(DomainError.invalidToken('wrong token purpose'))
    }

    const user = await this.userRepo.findById(payload.userId)
    if (!user || user.isDeleted) {
      return err(DomainError.userNotFound())
    }

    // Validate new password
    const pwResult = PlaintextPassword.create(input.newPassword)
    if (pwResult.isErr()) return err(pwResult.error)

    // Hash and update — changePassword() bumps tokenVersion
    const { currentPepperVersion } = this.passwordHasher
    const newHash = await this.passwordHasher.hash(
      pwResult.value,
      currentPepperVersion,
    )
    user.changePassword(newHash, currentPepperVersion)
    await this.userRepo.update(user)

    // Revoke ALL refresh tokens and clear session cache
    await this.refreshTokenRepo.revokeAllForUser(user.id)
    await this.sessionCache.clearUserSessions(user.id)

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
      eventType: 'password_reset_completed',
      ipAddress: context?.ipAddress ?? null,
      userAgent: null,
      riskLevel: 'medium',
      deviceFingerprint: null,
      metadata: {},
    })

    await this.eventBus.publish(user.domainEvents)
    user.clearDomainEvents()

    return ok({ success: true })
  }
}
