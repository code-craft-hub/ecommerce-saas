import { z } from 'zod'
import type { IUseCase } from '../../../domain/shared/IUseCase'
import {
  type Result,
  DomainError,
  err,
  ok,
} from '../../../domain/shared/Result'
import { Email } from '../../../domain/auth/value-objects/Email'
import { PlaintextPassword } from '../../../domain/auth/value-objects/Password'
import { User } from '../../../domain/auth/entities/User'
import type { IUserRepository } from '../../../domain/auth/repositories/IUserRepository'
import type { IRefreshTokenRepository } from '../../../domain/auth/repositories/IRefreshTokenRepository'
import type { IPasswordHashingService } from '../../../domain/auth/services/IPasswordHashingService'
import type { ITokenGenerationService } from '../../../domain/auth/services/ITokenGenerationService'
import type { ISessionCache } from '../../../domain/auth/services/ISessionCache'
import type { IEmailService } from '../../../domain/auth/services/IEmailService'
import type { IAuditLogRepository } from '../../../domain/auth/repositories/IAuditLogRepository'
import type { EventBus } from '../../shared/EventBus'
import { RefreshToken } from '../../../domain/auth/entities/RefreshToken'
import { hashToken } from '../../../infrastructure/services/tokenUtils'

// ---------------------------------------------------------------------------
// Input DTO with Zod validation
// ---------------------------------------------------------------------------

export const SignupRequestSchema = z.object({
  email: z.string().min(1).max(254),
  password: z.string().min(1).max(128),
  name: z.string().min(1).max(100).trim(),
})

export type SignupRequest = z.infer<typeof SignupRequestSchema>

export interface SignupResponse {
  accessToken: string
  user: {
    id: string
    email: string
    name: string
    emailVerified: boolean
  }
}

// ---------------------------------------------------------------------------
// Use Case
// ---------------------------------------------------------------------------

export class SignupUseCase
  implements IUseCase<SignupRequest, SignupResponse>
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
    private readonly config: { baseUrl: string; rtExpiryDays: number },
  ) {}

  async execute(
    input: SignupRequest,
    context?: { ipAddress?: string; userAgent?: string },
  ): Promise<Result<SignupResponse>> {
    // 1. Validate and create value objects
    const emailResult = Email.create(input.email)
    if (emailResult.isErr()) return err(emailResult.error)

    const passwordResult = PlaintextPassword.create(input.password)
    if (passwordResult.isErr()) return err(passwordResult.error)

    const email = emailResult.value
    const password = passwordResult.value

    // 2. Check uniqueness
    const existing = await this.userRepo.findByEmail(email.value)
    if (existing) {
      return err(DomainError.userAlreadyExists(email.value))
    }

    // 3. Hash password with current pepper
    const { currentPepperVersion } = this.passwordHasher
    const hashedPassword = await this.passwordHasher.hash(
      password,
      currentPepperVersion,
    )

    // 4. Create User aggregate
    const userId = crypto.randomUUID()
    const user = User.create({
      id: userId,
      email,
      name: input.name,
      passwordHash: hashedPassword,
      pepperVersion: currentPepperVersion,
    })

    // 5. Persist
    await this.userRepo.save(user)

    // 6. Issue token pair
    const familyId = crypto.randomUUID()
    const tokenPair = await this.tokenService.generateTokenPair({
      userId,
      tokenVersion: user.tokenVersion,
      rotationFamilyId: familyId,
    })

    // 7. Persist refresh token
    const rawRefreshToken = tokenPair.refreshToken
    const tokenHash = await hashToken(rawRefreshToken)
    const expiresAt = new Date(
      Date.now() + this.config.rtExpiryDays * 86_400_000,
    )
    const refreshToken = RefreshToken.create({
      id: tokenPair.refreshTokenMeta.jti,
      userId,
      tokenHash,
      rotationFamilyId: familyId,
      expiresAt,
      ipAddress: context?.ipAddress ?? null,
    })
    await this.refreshTokenRepo.save(refreshToken)

    // 8. Send verification email (event-driven, non-blocking)
    const verifyToken = await this.tokenService.generateVerificationToken({
      userId,
      email: email.value,
      purpose: 'email_verification',
    })
    this.emailService
      .sendVerificationEmail({
        to: email.value,
        name: input.name,
        verificationUrl: `${this.config.baseUrl}/api/auth/verify-email?token=${verifyToken}`,
      })
      .catch(() => {
        // Email failures must not fail the signup flow
      })

    // 9. Audit log
    await this.auditLog.log({
      userId,
      eventType: 'signup',
      ipAddress: context?.ipAddress ?? null,
      userAgent: context?.userAgent ?? null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: { email: email.value },
    })

    // 10. Publish domain events
    await this.eventBus.publish(user.domainEvents)
    user.clearDomainEvents()

    return ok({
      accessToken: tokenPair.accessToken,
      user: {
        id: userId,
        email: email.value,
        name: input.name,
        emailVerified: false,
      },
    })
  }
}
