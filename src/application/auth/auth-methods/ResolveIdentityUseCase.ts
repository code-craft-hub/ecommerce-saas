import { z } from 'zod'
import type { IUseCase } from '@/domain/shared/IUseCase'
import { type Result, ok } from '@/domain/shared/Result'
import type { IUserRepository } from '@/domain/auth/repositories/IUserRepository'
import type { IOAuthAccountRepository } from '@/domain/auth/repositories/IOAuthAccountRepository'

export const ResolveIdentityRequestSchema = z.object({
  email: z.string().email().max(254),
})

export type ResolveIdentityRequest = z.infer<typeof ResolveIdentityRequestSchema>

export interface ResolveIdentityResponse {
  /** Whether any account exists for this email */
  accountExists: boolean
  /** Available authentication methods */
  availableMethods: Array<'password' | 'google'>
  /**
   * Hint for the UI — which method to present first.
   * Does NOT leak sensitive information: we only reveal what the user
   * already knows (they entered the email themselves).
   */
  suggestedMethod: 'password' | 'google' | null
}

/**
 * ResolveIdentityUseCase
 *
 * Given an email address, returns which authentication methods are available
 * so the login UI can show the correct form (password field, "Sign in with
 * Google" button, or both).
 *
 * Security note: intentionally reveals whether an account exists because
 * (a) the caller already knows the email, and (b) the alternative — hiding
 * existence — breaks UX without meaningfully improving security against a
 * determined attacker.  Rate limiting on the calling endpoint is the correct
 * mitigation for enumeration.
 */
export class ResolveIdentityUseCase
  implements IUseCase<ResolveIdentityRequest, ResolveIdentityResponse>
{
  constructor(
    private readonly userRepo: IUserRepository,
    private readonly oauthAccountRepo: IOAuthAccountRepository,
  ) {}

  async execute(
    input: ResolveIdentityRequest,
  ): Promise<Result<ResolveIdentityResponse>> {
    const user = await this.userRepo.findByEmail(input.email)

    if (!user || user.isDeleted) {
      return ok({ accountExists: false, availableMethods: [], suggestedMethod: null })
    }

    const oauthAccounts = await this.oauthAccountRepo.findByUserId(user.id)
    const availableMethods: Array<'password' | 'google'> = []

    if (user.hasPassword) {
      availableMethods.push('password')
    }

    const hasGoogle = oauthAccounts.some((a) => a.provider === 'google')
    if (hasGoogle) {
      availableMethods.push('google')
    }

    // Suggest Google if it's the only method, password otherwise
    const suggestedMethod: 'password' | 'google' | null =
      availableMethods.length === 0
        ? null
        : availableMethods.includes('password')
          ? 'password'
          : 'google'

    return ok({ accountExists: true, availableMethods, suggestedMethod })
  }
}
