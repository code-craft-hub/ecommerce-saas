import type { OAuthProfile } from '@/domain/auth/value-objects/OAuthProfile'

export interface GoogleAuthorizationParams {
  redirectUri: string
  state: string
  /** Optional: 'consent' to force consent screen for re-linking */
  prompt?: 'none' | 'consent' | 'select_account'
}

export interface IGoogleOAuthClient {
  /** Build the authorization URL for the consent screen redirect */
  buildAuthorizationUrl(params: GoogleAuthorizationParams): string

  /** Exchange auth code for user profile (backend-only exchange) */
  exchangeCodeForProfile(params: {
    code: string
    redirectUri: string
  }): Promise<OAuthProfile>
}
