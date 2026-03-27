import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '@/domain/shared/Result'
import { OAuthAccount } from '@/domain/auth/entities/OAuthAccount'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IOAuthAccountRepository } from '@/domain/auth/repositories/IOAuthAccountRepository'
import type { IGoogleOAuthClient } from '@/domain/auth/services/IGoogleOAuthClient'
import type { ISessionCache } from '@/domain/auth/services/ISessionCache'
import type { IEmailService } from '@/domain/auth/services/IEmailService'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'
import type { EventBus } from '@/application/shared/EventBus'

export interface LinkOAuthAccountRequest {
  userId: string
  code: string
  state: string
  redirectUri: string
}

export interface LinkOAuthAccountResponse {
  linkedProvider: string
  providerEmail: string
}

export class LinkOAuthAccountUseCase
  implements IUseCase<LinkOAuthAccountRequest, LinkOAuthAccountResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly oauthAccountRepo: IOAuthAccountRepository,
    private readonly googleClient: IGoogleOAuthClient,
    private readonly sessionCache: ISessionCache,
    private readonly emailService: IEmailService,
    private readonly auditLog: IAuditLogRepository,
    private readonly eventBus: EventBus,
  ) {}

  async execute(
    input: LinkOAuthAccountRequest,
    context?: { ipAddress?: string },
  ): Promise<Result<LinkOAuthAccountResponse>> {
    // Verify CSRF state + retrieve PKCE verifier (atomic get-and-delete)
    const storedDataStr = await this.sessionCache.consumeOAuthState(input.state)
    if (!storedDataStr) {
      return err(DomainError.csrfValidationFailed())
    }

    let codeVerifier: string
    try {
      const storedData = JSON.parse(storedDataStr) as {
        state: string
        codeVerifier: string
      }
      if (storedData.state !== input.state) {
        return err(DomainError.csrfValidationFailed())
      }
      codeVerifier = storedData.codeVerifier
    } catch {
      return err(DomainError.csrfValidationFailed())
    }

    const user = await this.userRepo.findById(input.userId)
    if (!user || user.isDeleted) {
      return err(DomainError.userNotFound())
    }

    // Exchange code (PKCE verifier sent to Google for validation)
    let profile
    try {
      profile = await this.googleClient.exchangeCodeForProfile({
        code: input.code,
        redirectUri: input.redirectUri,
        codeVerifier,
      })
    } catch {
      return err(
        new DomainError('OAUTH_PROVIDER_ERROR', 'Google OAuth exchange failed'),
      )
    }

    // Check if this Google account is already linked to another user
    const existingOAuth = await this.oauthAccountRepo.findByProvider(
      'google',
      profile.providerUserId,
    )
    if (existingOAuth && existingOAuth.userId !== input.userId) {
      return err(DomainError.oauthAccountAlreadyLinked('Google'))
    }
    if (existingOAuth && existingOAuth.userId === input.userId) {
      // Already linked to this user — idempotent success
      return ok({
        linkedProvider: 'google',
        providerEmail: profile.email,
      })
    }

    // Link the account
    const oauthAccount = OAuthAccount.create({
      id: crypto.randomUUID(),
      userId: input.userId,
      profile,
    })
    await this.oauthAccountRepo.save(oauthAccount)

    user.recordOAuthLink(profile)
    await this.userRepo.update(user)

    // Notify user of new link
    this.emailService
      .sendNewOAuthLinkNotification({
        to: user.email.value,
        name: user.name,
        provider: 'Google',
        providerEmail: profile.email,
      })
      .catch(() => {})

    await this.auditLog.log({
      userId: input.userId,
      eventType: 'oauth_link',
      ipAddress: context?.ipAddress ?? null,
      userAgent: null,
      riskLevel: 'low',
      deviceFingerprint: null,
      metadata: { provider: 'google', providerEmail: profile.email },
    })

    await this.eventBus.publish(user.domainEvents)
    user.clearDomainEvents()

    return ok({
      linkedProvider: 'google',
      providerEmail: profile.email,
    })
  }
}
