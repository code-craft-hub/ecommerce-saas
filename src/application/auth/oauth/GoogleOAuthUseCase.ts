import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '@/domain/shared/Result'
import { Email } from '@/domain/auth/value-objects/Email'
import { User } from '@/domain/auth/entities/User'
import { OAuthAccount } from '@/domain/auth/entities/OAuthAccount'
import { RefreshToken } from '@/domain/auth/entities/RefreshToken'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IRefreshTokenRepository } from '@/domain/auth/repositories/IRefreshTokenRepository'
import type { IOAuthAccountRepository } from '@/domain/auth/repositories/IOAuthAccountRepository'
import type { ITokenGenerationService } from '@/domain/auth/services/ITokenGenerationService'
import type { ISessionCache } from '@/domain/auth/services/ISessionCache'
import type { IGoogleOAuthClient } from '@/domain/auth/services/IGoogleOAuthClient'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'
import type { EventBus } from '@/application/shared/EventBus'
import { UserAuthenticatedEvent } from '@/domain/auth/events/UserAuthenticatedEvent'
import { hashToken } from '@/infrastructure/services/tokenUtils'

export interface GoogleCallbackRequest {
  code: string
  state: string
  redirectUri: string
}

export type GoogleOAuthResult =
  | { type: 'authenticated'; accessToken: string; refreshToken: string; user: { id: string; email: string; name: string } }
  | { type: 'link_required'; email: string; message: string }

export class GoogleOAuthUseCase
  implements IUseCase<GoogleCallbackRequest, GoogleOAuthResult>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly refreshTokenRepo: IRefreshTokenRepository,
    private readonly oauthAccountRepo: IOAuthAccountRepository,
    private readonly tokenService: ITokenGenerationService,
    private readonly sessionCache: ISessionCache,
    private readonly googleClient: IGoogleOAuthClient,
    private readonly auditLog: IAuditLogRepository,
    private readonly eventBus: EventBus,
    private readonly config: {
      rtExpiryDays: number
      csrfStatePrefix: string
    },
  ) {}

  async execute(
    input: GoogleCallbackRequest,
    context?: { ipAddress?: string; userAgent?: string },
  ): Promise<Result<GoogleOAuthResult>> {
    // 1. Verify CSRF state token
    const storedState = await this.sessionCache.consumeOAuthState(input.state)
    if (!storedState) {
      return err(DomainError.csrfValidationFailed())
    }

    // 2. Exchange code for profile
    let profile
    try {
      profile = await this.googleClient.exchangeCodeForProfile({
        code: input.code,
        redirectUri: input.redirectUri,
      })
    } catch (e) {
      return err(
        new DomainError('OAUTH_PROVIDER_ERROR', 'Google OAuth exchange failed'),
      )
    }

    // 3. Look up existing OAuth account
    const existingOAuth = await this.oauthAccountRepo.findByProvider(
      'google',
      profile.providerUserId,
    )

    if (existingOAuth) {
      // Happy path: existing linked account — just log in
      const user = await this.userRepo.findById(existingOAuth.userId)
      if (!user || user.isDeleted) {
        return err(DomainError.userNotFound())
      }

      // Update profile claims (name, picture may have changed)
      existingOAuth.recordLogin(profile)
      await this.oauthAccountRepo.update(existingOAuth)

      return this.issueTokensAndAudit(user, context)
    }

    // 4. No existing OAuth account — check by email
    const emailResult = Email.create(profile.email)
    if (emailResult.isErr()) {
      return err(emailResult.error)
    }

    const userByEmail = await this.userRepo.findByEmail(profile.email)

    if (userByEmail && !userByEmail.isDeleted) {
      // Email exists — offer account linking
      // We can't automatically link without user consent
      return ok({
        type: 'link_required',
        email: profile.email,
        message:
          'An account with this email already exists. Please log in to link your Google account.',
      })
    }

    // 5. New user — create account
    const userId = crypto.randomUUID()
    const user = User.create({
      id: userId,
      email: emailResult.value,
      name: profile.name,
      passwordHash: null,
      pepperVersion: 1,
    })
    // Google provides verified email claim
    if (profile.emailVerified) {
      user.verifyEmail()
    }
    await this.userRepo.save(user)

    // 6. Create OAuth account record
    const oauthAccount = OAuthAccount.create({
      id: crypto.randomUUID(),
      userId,
      profile,
    })
    await this.oauthAccountRepo.save(oauthAccount)

    user.recordOAuthLink(profile)

    await this.eventBus.publish(user.domainEvents)
    user.clearDomainEvents()

    return this.issueTokensAndAudit(user, context)
  }

  private async issueTokensAndAudit(
    user: { id: string; email: { value: string }; name: string; emailVerified: boolean; tokenVersion: number },
    context?: { ipAddress?: string; userAgent?: string },
  ): Promise<Result<GoogleOAuthResult>> {
    const familyId = crypto.randomUUID()
    const tokenPair = await this.tokenService.generateTokenPair({
      userId: user.id,
      tokenVersion: user.tokenVersion,
      rotationFamilyId: familyId,
    })

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
    })
    await this.refreshTokenRepo.save(refreshToken)

    await this.auditLog.log({
      userId: user.id,
      eventType: 'login',
      ipAddress: context?.ipAddress ?? null,
      userAgent: context?.userAgent ?? null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: { method: 'google' },
    })

    await this.eventBus.publishOne(
      new UserAuthenticatedEvent(
        user.id,
        'google',
        context?.ipAddress ?? null,
        context?.userAgent ?? null,
        'low',
      ),
    )

    return ok({
      type: 'authenticated',
      accessToken: tokenPair.accessToken,
      refreshToken: tokenPair.refreshToken,
      user: { id: user.id, email: user.email.value, name: user.name },
    })
  }
}
