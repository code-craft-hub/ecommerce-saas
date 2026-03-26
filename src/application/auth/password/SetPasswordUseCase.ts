import { z } from 'zod'
import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '@/domain/shared/Result'
import { PlaintextPassword } from '@/domain/auth/value-objects/Password'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IPasswordHashingService } from '@/domain/auth/services/IPasswordHashingService'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'
import type { EventBus } from '@/application/shared/EventBus'

export const SetPasswordRequestSchema = z.object({
  password: z.string().min(1).max(128),
})

export type SetPasswordRequest = z.infer<typeof SetPasswordRequestSchema>

export interface SetPasswordResponse {
  success: true
}

/**
 * Set password for OAuth-only users who want to add password authentication.
 * Fails if user already has a password — use ChangePassword instead.
 */
export class SetPasswordUseCase
  implements IUseCase<SetPasswordRequest & { userId: string }, SetPasswordResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly passwordHasher: IPasswordHashingService,
    private readonly auditLog: IAuditLogRepository,
    private readonly eventBus: EventBus,
  ) {}

  async execute(
    input: SetPasswordRequest & { userId: string },
    context?: { ipAddress?: string },
  ): Promise<Result<SetPasswordResponse>> {
    const user = await this.userRepo.findById(input.userId)
    if (!user || user.isDeleted) {
      return err(DomainError.userNotFound())
    }
    if (user.hasPassword) {
      return err(DomainError.passwordAlreadySet())
    }

    const pwResult = PlaintextPassword.create(input.password)
    if (pwResult.isErr()) return err(pwResult.error)

    const { currentPepperVersion } = this.passwordHasher
    const hash = await this.passwordHasher.hash(pwResult.value, currentPepperVersion)

    // setPassword() emits PasswordChangedEvent with allSessionsInvalidated=false
    user.setPassword(hash, currentPepperVersion)
    await this.userRepo.update(user)

    await this.auditLog.log({
      userId: user.id,
      eventType: 'password_change',
      ipAddress: context?.ipAddress ?? null,
      userAgent: null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: { action: 'set_initial_password' },
    })

    await this.eventBus.publish(user.domainEvents)
    user.clearDomainEvents()

    return ok({ success: true })
  }
}
