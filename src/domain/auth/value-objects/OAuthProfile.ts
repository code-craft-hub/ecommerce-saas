/**
 * OAuthProfile Value Object — normalized claims from any OAuth 2.0 provider.
 */
export type OAuthProvider = 'google' | 'github' | 'microsoft'

export class OAuthProfile {
  private constructor(
    readonly provider: OAuthProvider,
    /** Provider's stable user identifier (e.g. Google's `sub`) */
    readonly providerUserId: string,
    readonly email: string,
    readonly emailVerified: boolean,
    readonly name: string,
    readonly pictureUrl: string | null,
    /** Raw provider metadata for auditing/future use */
    readonly rawClaims: Record<string, unknown>,
  ) {}

  static create(params: {
    provider: OAuthProvider
    providerUserId: string
    email: string
    emailVerified: boolean
    name: string
    pictureUrl?: string | null
    rawClaims: Record<string, unknown>
  }): OAuthProfile {
    return new OAuthProfile(
      params.provider,
      params.providerUserId,
      params.email.trim().toLowerCase(),
      params.emailVerified,
      params.name,
      params.pictureUrl ?? null,
      params.rawClaims,
    )
  }

  equals(other: OAuthProfile): boolean {
    return (
      this.provider === other.provider &&
      this.providerUserId === other.providerUserId
    )
  }
}
