import { z } from 'zod'
import type { IUseCase } from '../../../domain/shared/IUseCase'
import { type Result, ok } from '../../../domain/shared/Result'
import type { IUserRepository } from '../../../domain/auth/repositories/IUserRepository'
import type { ITokenGenerationService } from '../../../domain/auth/services/ITokenGenerationService'
import type { IEmailService } from '../../../domain/auth/services/IEmailService'
import type { IAuditLogRepository } from '../../../domain/auth/repositories/IAuditLogRepository'

export const ForgotPasswordRequestSchema = z.object({
  email: z.string().min(1).max(254),
})

export type ForgotPasswordRequest = z.infer<typeof ForgotPasswordRequestSchema>

export interface ForgotPasswordResponse {
  /** Always true — never reveal if email exists */
  success: true
}

export class ForgotPasswordUseCase
  implements IUseCase<ForgotPasswordRequest, ForgotPasswordResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly tokenService: ITokenGenerationService,
    private readonly emailService: IEmailService,
    private readonly auditLog: IAuditLogRepository,
    private readonly config: { baseUrl: string },
  ) {}

  async execute(
    input: ForgotPasswordRequest,
    context?: { ipAddress?: string },
  ): Promise<Result<ForgotPasswordResponse>> {
    // Always return success — don't reveal if email exists (user enumeration prevention)
    const user = await this.userRepo.findByEmail(
      input.email.trim().toLowerCase(),
    )

    if (user && !user.isDeleted) {
      const resetToken = await this.tokenService.generateVerificationToken({
        userId: user.id,
        email: user.email.value,
        purpose: 'password_reset',
      })

      this.emailService
        .sendPasswordResetEmail({
          to: user.email.value,
          name: user.name,
          resetUrl: `${this.config.baseUrl}/reset-password?token=${resetToken}`,
          expiresInMinutes: 60,
        })
        .catch(() => {})

      await this.auditLog.log({
        userId: user.id,
        eventType: 'password_reset_requested',
        ipAddress: context?.ipAddress ?? null,
        userAgent: null,
        riskLevel: 'low',
        deviceFingerprint: null,
        metadata: {},
      })
    }

    return ok({ success: true })
  }
}
