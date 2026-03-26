import { z } from 'zod'
import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '@/domain/shared/Result'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { ITokenGenerationService } from '@/domain/auth/services/ITokenGenerationService'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'

export const VerifyEmailRequestSchema = z.object({
  token: z.string().min(1),
})

export type VerifyEmailRequest = z.infer<typeof VerifyEmailRequestSchema>

export interface VerifyEmailResponse {
  success: true
  email: string
}

export class VerifyEmailUseCase
  implements IUseCase<VerifyEmailRequest, VerifyEmailResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly tokenService: ITokenGenerationService,
    private readonly auditLog: IAuditLogRepository,
  ) {}

  async execute(
    input: VerifyEmailRequest,
    context?: { ipAddress?: string },
  ): Promise<Result<VerifyEmailResponse>> {
    let payload: { userId: string; email: string; purpose: string }
    try {
      payload = await this.tokenService.verifyVerificationToken(input.token)
    } catch {
      return err(
        DomainError.invalidToken('verification token invalid or expired'),
      )
    }

    if (payload.purpose !== 'email_verification') {
      return err(DomainError.invalidToken('wrong token purpose'))
    }

    const user = await this.userRepo.findById(payload.userId)
    if (!user || user.isDeleted) {
      return err(DomainError.userNotFound())
    }

    if (user.emailVerified) {
      // Idempotent
      return ok({ success: true, email: user.email.value })
    }

    user.verifyEmail()
    await this.userRepo.update(user)

    await this.auditLog.log({
      userId: user.id,
      eventType: 'email_verified',
      ipAddress: context?.ipAddress ?? null,
      userAgent: null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: { email: user.email.value },
    })

    return ok({ success: true, email: user.email.value })
  }
}
