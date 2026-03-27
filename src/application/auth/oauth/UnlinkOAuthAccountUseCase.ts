import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '@/domain/shared/Result'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IOAuthAccountRepository } from '@/domain/auth/repositories/IOAuthAccountRepository'
import type { IAuditLogRepository } from '@/domain/auth/repositories/IAuditLogRepository'
import type { EventBus } from '@/application/shared/EventBus'
import type { OAuthProvider } from '@/domain/auth/value-objects/OAuthProfile'

export interface UnlinkOAuthAccountRequest {
  userId: string
  provider: OAuthProvider
}

export interface UnlinkOAuthAccountResponse {
  unlinkedProvider: string
}

/**
 * UnlinkOAuthAccountUseCase
 *
 * Removes a linked OAuth provider from the user's account.
 *
 * Invariants enforced (prevent orphaning):
 * - User must have at least one OTHER authentication method remaining.
 *   Specifically: either a password hash OR a different OAuth provider.
 * - Cannot unlink a provider that isn't linked.
 */
export class UnlinkOAuthAccountUseCase
  implements IUseCase<UnlinkOAuthAccountRequest, UnlinkOAuthAccountResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly oauthAccountRepo: IOAuthAccountRepository,
    private readonly auditLog: IAuditLogRepository,
    private readonly eventBus: EventBus,
  ) {}

  async execute(
    input: UnlinkOAuthAccountRequest,
    context?: { ipAddress?: string },
  ): Promise<Result<UnlinkOAuthAccountResponse>> {
    const user = await this.userRepo.findById(input.userId)
    if (!user || user.isDeleted) {
      return err(DomainError.userNotFound())
    }

    // Find the linked OAuth account to remove
    const oauthAccounts = await this.oauthAccountRepo.findByUserId(user.id)
    const target = oauthAccounts.find((a) => a.provider === input.provider)

    if (!target) {
      return err(
        new DomainError('OAUTH_ACCOUNT_NOT_FOUND', `No ${input.provider} account linked`),
      )
    }

    // Orphan prevention: ensure at least one auth method remains after unlinking
    const remainingOAuth = oauthAccounts.filter((a) => a.provider !== input.provider)
    const willHavePassword = user.hasPassword
    const willHaveOtherOAuth = remainingOAuth.length > 0

    if (!willHavePassword && !willHaveOtherOAuth) {
      return err(
        new DomainError(
          'FORBIDDEN',
          'Cannot remove the only sign-in method. Add a password first.',
        ),
      )
    }

    // Remove the OAuth account
    await this.oauthAccountRepo.delete(target.id)

    await this.auditLog.log({
      userId: user.id,
      eventType: 'oauth_unlink',
      ipAddress: context?.ipAddress ?? null,
      userAgent: null,
      riskLevel: 'medium',
      deviceFingerprint: null,
      metadata: { provider: input.provider, providerEmail: target.email },
    })

    return ok({ unlinkedProvider: input.provider })
  }
}
