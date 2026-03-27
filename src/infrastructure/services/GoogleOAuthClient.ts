import { jwtVerify, createRemoteJWKSet } from 'jose'
import type { IGoogleOAuthClient, GoogleAuthorizationParams } from '@/domain/auth/services/IGoogleOAuthClient'
import type { OAuthProfile } from '@/domain/auth/value-objects/OAuthProfile'
import { OAuthProfile as OAuthProfileVO } from '@/domain/auth/value-objects/OAuthProfile'

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs'
const GOOGLE_ISSUER = 'https://accounts.google.com'

/**
 * Google OAuth 2.0 client.
 *
 * PKCE (RFC 9700 §2.1.1):
 * - code_challenge / code_challenge_method=S256 are added to the auth URL
 * - code_verifier is sent with the token exchange request
 * - Google verifies that SHA-256(code_verifier) == code_challenge
 *
 * ID token signature is verified using Google's JWKS endpoint.
 */
export class GoogleOAuthClient implements IGoogleOAuthClient {
  private readonly jwks = createRemoteJWKSet(new URL(GOOGLE_JWKS_URL))

  constructor(
    private readonly config: {
      clientId: string
      clientSecret: string
    },
  ) {}

  buildAuthorizationUrl(params: GoogleAuthorizationParams): string {
    const searchParams = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: params.redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      state: params.state,
      access_type: 'offline',
      code_challenge: params.codeChallenge,
      code_challenge_method: params.codeChallengeMethod,
      ...(params.prompt ? { prompt: params.prompt } : {}),
    })
    return `${GOOGLE_AUTH_URL}?${searchParams.toString()}`
  }

  async exchangeCodeForProfile(params: {
    code: string
    redirectUri: string
    codeVerifier: string
  }): Promise<OAuthProfile> {
    // Exchange authorization code for tokens (backend-only — never expose code to client)
    const tokenResponse = await fetch(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: params.code,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        redirect_uri: params.redirectUri,
        grant_type: 'authorization_code',
        // PKCE verifier — Google rejects if SHA-256(verifier) ≠ stored challenge
        code_verifier: params.codeVerifier,
      }),
    })

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text()
      throw new Error(`Google token exchange failed: ${error}`)
    }

    const tokens = await tokenResponse.json() as {
      id_token: string
      access_token: string
    }

    if (!tokens.id_token) {
      throw new Error('Google did not return an id_token')
    }

    // Verify ID token signature using Google's JWKS
    const { payload } = await jwtVerify(tokens.id_token, this.jwks, {
      issuer: [GOOGLE_ISSUER, 'accounts.google.com'],
      audience: this.config.clientId,
      algorithms: ['RS256'],
    })

    const claims = payload as {
      sub: string
      email: string
      email_verified: boolean
      name: string
      picture?: string
    }

    return OAuthProfileVO.create({
      provider: 'google',
      providerUserId: claims.sub,
      email: claims.email,
      emailVerified: claims.email_verified ?? false,
      name: claims.name,
      pictureUrl: claims.picture ?? null,
      rawClaims: payload as Record<string, unknown>,
    })
  }
}
