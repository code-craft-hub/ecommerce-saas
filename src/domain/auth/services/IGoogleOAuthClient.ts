import type { OAuthProfile } from '@/domain/auth/value-objects/OAuthProfile'

export interface GoogleAuthorizationParams {
  redirectUri: string
  state: string
  /**
   * PKCE code challenge (base64url(SHA-256(code_verifier))).
   * Required per RFC 9700 §2.1.1 — even for confidential clients.
   */
  codeChallenge: string
  /** Always 'S256' — plain is disallowed */
  codeChallengeMethod: 'S256'
  /** Optional: 'consent' to force consent screen for re-linking */
  prompt?: 'none' | 'consent' | 'select_account'
}

export interface IGoogleOAuthClient {
  /** Build the authorization URL for the consent screen redirect */
  buildAuthorizationUrl(params: GoogleAuthorizationParams): string

  /**
   * Exchange auth code for user profile (backend-only exchange).
   * codeVerifier is required for PKCE validation.
   */
  exchangeCodeForProfile(params: {
    code: string
    redirectUri: string
    codeVerifier: string
  }): Promise<OAuthProfile>
}
