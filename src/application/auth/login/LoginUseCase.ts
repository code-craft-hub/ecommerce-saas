import { z } from 'zod'
import type { IUseCase } from '@/domain/shared/IUseCase'
import {
  type Result,
  DomainError,
  err,
  ok,
} from '@/domain/shared/Result'
import { Email } from '@/domain/auth/value-objects/Email'
import { PlaintextPassword } from '@/domain/auth/value-objects/Password'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IRefreshTokenRepository } from '@/domain/auth/repositories/IRefreshTokenRepository'
import type { IPasswordHashingService } from '@/domain/auth/services/IPasswordHashingService'
import type { ITokenGenerationService } from '@/domain/auth/services/ITokenGenerationService'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'
import type { EventBus } from '@/application/shared/EventBus'
import { UserAuthenticatedEvent } from '@/domain/auth/events/UserAuthenticatedEvent'
import { RefreshToken } from '@/domain/auth/entities/RefreshToken'
import { hashToken } from '@/infrastructure/services/tokenUtils'

export const LoginRequestSchema = z.object({
  email: z.string().min(1).max(254),
  password: z.string().min(1).max(128),
})

export type LoginRequest = z.infer<typeof LoginRequestSchema>

export interface LoginResponse {
  accessToken: string
  refreshToken: string
  user: {
    id: string
    email: string
    name: string
    emailVerified: boolean
  }
}

export class LoginUseCase implements IUseCase<LoginRequest, LoginResponse> {
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly refreshTokenRepo: IRefreshTokenRepository,
    private readonly passwordHasher: IPasswordHashingService,
    private readonly tokenService: ITokenGenerationService,
    private readonly auditLog: IAuditLogRepository,
    private readonly eventBus: EventBus,
    private readonly config: { rtExpiryDays: number },
  ) {}

  async execute(
    input: LoginRequest,
    context?: { ipAddress?: string; userAgent?: string },
  ): Promise<Result<LoginResponse>> {
    const emailResult = Email.create(input.email)
    if (emailResult.isErr()) return err(DomainError.invalidCredentials())

    // Use timing-safe approach: always try to find user before checking password
    const user = await this.userRepo.findByEmail(emailResult.value.value)

    // Constant-time: always hash even if user not found (prevent timing oracle)
    const passwordResult = PlaintextPassword.create(input.password)
    if (passwordResult.isErr()) {
      await this.auditLog.log({
        userId: null,
        eventType: 'failed_login',
        ipAddress: context?.ipAddress ?? null,
        userAgent: context?.userAgent ?? null,
        riskLevel: 'medium',
        deviceFingerprint: null,
        metadata: { email: input.email, reason: 'invalid_password_format' },
      })
      return err(DomainError.invalidCredentials())
    }

    if (!user || user.isDeleted) {
      // Perform dummy hash to equalize timing with valid-user path
      await this.passwordHasher.hash(passwordResult.value, 1)
      await this.auditLog.log({
        userId: null,
        eventType: 'failed_login',
        ipAddress: context?.ipAddress ?? null,
        userAgent: context?.userAgent ?? null,
        riskLevel: 'medium',
        deviceFingerprint: null,
        metadata: { email: input.email, reason: 'user_not_found' },
      })
      return err(DomainError.invalidCredentials())
    }

    if (!user.hasPassword) {
      return err(DomainError.passwordNotSet())
    }

    // Verify password
    const isValid = await this.passwordHasher.verify(
      passwordResult.value,
      user.passwordHash!,
      user.passwordPepperVersion,
    )

    if (!isValid) {
      await this.auditLog.log({
        userId: user.id,
        eventType: 'failed_login',
        ipAddress: context?.ipAddress ?? null,
        userAgent: context?.userAgent ?? null,
        riskLevel: 'medium',
        deviceFingerprint: null,
        metadata: { reason: 'wrong_password' },
      })
      return err(DomainError.invalidCredentials())
    }

    // Issue token pair
    const familyId = crypto.randomUUID()
    const tokenPair = await this.tokenService.generateTokenPair({
      userId: user.id,
      tokenVersion: user.tokenVersion,
      rotationFamilyId: familyId,
    })

    // Persist refresh token
    const tokenHash = await hashToken(tokenPair.refreshToken)
    const expiresAt = new Date(
      Date.now() + this.config.rtExpiryDays * 86_400_000,
    )
    const refreshToken = RefreshToken.create({
      id: tokenPair.refreshTokenMeta.jti,
      userId: user.id,
      tokenHash,
      rotationFamilyId: familyId,
      expiresAt,
      ipAddress: context?.ipAddress ?? null,
      userAgent: context?.userAgent ?? null,
    })
    await this.refreshTokenRepo.save(refreshToken)

    // Audit + events
    await this.auditLog.log({
      userId: user.id,
      eventType: 'login',
      ipAddress: context?.ipAddress ?? null,
      userAgent: context?.userAgent ?? null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: { method: 'password' },
    })

    await this.eventBus.publishOne(
      new UserAuthenticatedEvent(
        user.id,
        'password',
        context?.ipAddress ?? null,
        context?.userAgent ?? null,
        'low',
      ),
    )

    return ok({
      accessToken: tokenPair.accessToken,
      refreshToken: tokenPair.refreshToken,
      user: {
        id: user.id,
        email: user.email.value,
        name: user.name,
        emailVerified: user.emailVerified,
      },
    })
  }
}
