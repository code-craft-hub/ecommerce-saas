import {
  SignJWT,
  jwtVerify,
  importPKCS8,
  importSPKI,
} from 'jose'
// jose v6 uses the Web Crypto API KeyObject — use a broad type for the cache
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type KeyLike = any
import type { ITokenGenerationService, AccessTokenClaims } from '../../domain/auth/services/ITokenGenerationService'
import type { TokenPair } from '../../domain/auth/value-objects/TokenPair'
import { TokenPair as TokenPairVO } from '../../domain/auth/value-objects/TokenPair'
import { generateOpaqueToken } from './tokenUtils'

/**
 * JWT token generator using RS256 (asymmetric signing).
 *
 * RS256 benefits:
 * - Resource servers can verify tokens using only the public key
 * - Private key never leaves the auth server
 * - Supports OIDC discovery / JWKS endpoint
 *
 * Access token: JWT (RS256), 15 minutes
 * Refresh token: opaque random bytes (NOT a JWT), stored server-side
 * Verification tokens: short-lived JWT for email verify / password reset
 */
export class JwtTokenGenerator implements ITokenGenerationService {
  private privateKey: KeyLike | null = null
  private publicKey: KeyLike | null = null

  constructor(
    private readonly config: {
      privateKeyPem: string
      publicKeyPem: string
      issuer: string
      audience: string
      accessTokenExpirySeconds: number
      verificationTokenExpirySeconds: number
    },
  ) {}

  private async getPrivateKey(): Promise<KeyLike> {
    if (!this.privateKey) {
      this.privateKey = await importPKCS8(this.config.privateKeyPem, 'RS256')
    }
    return this.privateKey
  }

  private async getPublicKey(): Promise<KeyLike> {
    if (!this.publicKey) {
      this.publicKey = await importSPKI(this.config.publicKeyPem, 'RS256')
    }
    return this.publicKey
  }

  async generateTokenPair(params: {
    userId: string
    tokenVersion: number
    rotationFamilyId: string
    deviceId?: string | null
  }): Promise<TokenPair> {
    const now = Math.floor(Date.now() / 1000)
    const accessJti = crypto.randomUUID()
    const refreshJti = crypto.randomUUID()
    const accessExp = now + this.config.accessTokenExpirySeconds

    const privateKey = await this.getPrivateKey()

    // Access token — RS256 JWT
    const accessToken = await new SignJWT({
      uid: params.userId,
      ver: params.tokenVersion,
      scope: 'openid profile email',
    })
      .setProtectedHeader({ alg: 'RS256' })
      .setSubject(params.userId)
      .setAudience(this.config.audience)
      .setIssuer(this.config.issuer)
      .setIssuedAt(now)
      .setExpirationTime(accessExp)
      .setJti(accessJti)
      .sign(privateKey)

    // Refresh token — opaque, cryptographically random
    const refreshTokenRaw = generateOpaqueToken()
    const refreshExp = Math.floor(
      (Date.now() + 30 * 24 * 60 * 60 * 1000) / 1000,
    )

    return TokenPairVO.create(
      accessToken,
      refreshTokenRaw,
      {
        jti: accessJti,
        issuedAt: now,
        expiresAt: accessExp,
        rotationFamilyId: params.rotationFamilyId,
      },
      {
        jti: refreshJti,
        issuedAt: now,
        expiresAt: refreshExp,
        rotationFamilyId: params.rotationFamilyId,
      },
    )
  }

  async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    const publicKey = await this.getPublicKey()

    const { payload } = await jwtVerify(token, publicKey, {
      issuer: this.config.issuer,
      audience: this.config.audience,
      algorithms: ['RS256'],
    })

    // Map payload to typed claims
    return {
      sub: payload.sub as string,
      aud: Array.isArray(payload.aud) ? payload.aud[0] : (payload.aud as string),
      iss: payload.iss as string,
      jti: payload.jti as string,
      iat: payload.iat as number,
      exp: payload.exp as number,
      uid: payload['uid'] as string,
      ver: payload['ver'] as number,
      scope: payload['scope'] as string,
    }
  }

  async generateVerificationToken(payload: {
    userId: string
    email: string
    purpose: 'email_verification' | 'password_reset'
  }): Promise<string> {
    const privateKey = await this.getPrivateKey()

    return new SignJWT({
      email: payload.email,
      purpose: payload.purpose,
    })
      .setProtectedHeader({ alg: 'RS256' })
      .setSubject(payload.userId)
      .setIssuer(this.config.issuer)
      .setIssuedAt()
      .setExpirationTime(
        `${this.config.verificationTokenExpirySeconds}s`,
      )
      .setJti(crypto.randomUUID())
      .sign(privateKey)
  }

  async verifyVerificationToken(token: string): Promise<{
    userId: string
    email: string
    purpose: 'email_verification' | 'password_reset'
  }> {
    const publicKey = await this.getPublicKey()

    const { payload } = await jwtVerify(token, publicKey, {
      issuer: this.config.issuer,
      algorithms: ['RS256'],
    })

    return {
      userId: payload.sub as string,
      email: payload['email'] as string,
      purpose: payload['purpose'] as 'email_verification' | 'password_reset',
    }
  }
}
