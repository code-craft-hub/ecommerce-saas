import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, DomainError, err, ok } from '@/domain/shared/Result'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IOAuthAccountRepository } from '@/domain/auth/repositories/IOAuthAccountRepository'

export interface GetAvailableAuthMethodsRequest {
  userId: string
}

export interface AuthMethodDTO {
  method: 'password' | 'google'
  /** Provider-side email (may differ from user.email for Google) */
  email?: string
  /** ISO timestamp of when the method was added */
  linkedAt?: string
  isPrimary: boolean
}

export interface GetAvailableAuthMethodsResponse {
  methods: AuthMethodDTO[]
  /**
   * True if the account would be "orphaned" by removing any single method.
   * The UI should use this to prevent unlinking the last auth method.
   */
  canUnlinkAny: boolean
}

/**
 * GetAvailableAuthMethodsUseCase
 *
 * Returns the full list of authentication methods configured on the
 * authenticated user's account — equivalent to Google's "How you sign in"
 * panel in account settings.
 */
export class GetAvailableAuthMethodsUseCase
  implements
    IUseCase<GetAvailableAuthMethodsRequest, GetAvailableAuthMethodsResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly oauthAccountRepo: IOAuthAccountRepository,
  ) {}

  async execute(
    input: GetAvailableAuthMethodsRequest,
  ): Promise<Result<GetAvailableAuthMethodsResponse>> {
    const user = await this.userRepo.findById(input.userId)
    if (!user || user.isDeleted) {
      return err(DomainError.userNotFound())
    }

    const oauthAccounts = await this.oauthAccountRepo.findByUserId(user.id)
    const methods: AuthMethodDTO[] = []

    if (user.hasPassword) {
      methods.push({
        method: 'password',
        email: user.email.value,
        isPrimary: true,
      })
    }

    for (const oauth of oauthAccounts) {
      if (oauth.provider === 'google') {
        methods.push({
          method: 'google',
          email: oauth.email,
          linkedAt: oauth.linkedAt.toISOString(),
          isPrimary: !user.hasPassword && methods.length === 0,
        })
      }
    }

    // User can unlink a method only if they would still have at least one left
    const canUnlinkAny = methods.length > 1

    return ok({ methods, canUnlinkAny })
  }
}
