/**
 * TokenPair Value Object — access + refresh token with metadata.
 * Immutable snapshot of an issued token pair.
 */
export interface TokenMetadata {
  /** JWT ID — used for denylist revocation */
  jti: string
  /** Unix epoch seconds */
  issuedAt: number
  /** Unix epoch seconds */
  expiresAt: number
  /** Rotation family tracking */
  rotationFamilyId: string
}

export class TokenPair {
  private constructor(
    /** Short-lived JWT (RS256) — safe for Authorization header */
    readonly accessToken: string,
    /** Long-lived opaque token — store in httpOnly cookie */
    readonly refreshToken: string,
    readonly accessTokenMeta: TokenMetadata,
    readonly refreshTokenMeta: TokenMetadata,
  ) {}

  static create(
    accessToken: string,
    refreshToken: string,
    accessTokenMeta: TokenMetadata,
    refreshTokenMeta: TokenMetadata,
  ): TokenPair {
    return new TokenPair(
      accessToken,
      refreshToken,
      accessTokenMeta,
      refreshTokenMeta,
    )
  }

  get accessTokenExpiresAt(): Date {
    return new Date(this.accessTokenMeta.expiresAt * 1000)
  }

  get refreshTokenExpiresAt(): Date {
    return new Date(this.refreshTokenMeta.expiresAt * 1000)
  }

  isAccessTokenExpired(): boolean {
    return Date.now() / 1000 > this.accessTokenMeta.expiresAt
  }

  isRefreshTokenExpired(): boolean {
    return Date.now() / 1000 > this.refreshTokenMeta.expiresAt
  }
}
