import type { IEmailService } from '../../../domain/auth/services/IEmailService'

/**
 * Console email service for development / testing.
 * Swap for SendGrid, SES, or Resend in production by implementing IEmailService.
 */
export class ConsoleEmailService implements IEmailService {
  private log(label: string, params: object): void {
    console.log(`[Email:${label}]`, JSON.stringify(params, null, 2))
  }

  async sendVerificationEmail(params: {
    to: string
    name: string
    verificationUrl: string
  }): Promise<void> {
    this.log('verify', params)
  }

  async sendPasswordResetEmail(params: {
    to: string
    name: string
    resetUrl: string
    expiresInMinutes: number
  }): Promise<void> {
    this.log('password-reset', params)
  }

  async sendPasswordChangedNotification(params: {
    to: string
    name: string
    ipAddress: string | null
    timestamp: Date
  }): Promise<void> {
    this.log('password-changed', params)
  }

  async sendNewOAuthLinkNotification(params: {
    to: string
    name: string
    provider: string
    providerEmail: string
  }): Promise<void> {
    this.log('oauth-linked', params)
  }

  async sendSuspiciousActivityAlert(params: {
    to: string
    name: string
    ipAddress: string | null
    userAgent: string | null
    timestamp: Date
  }): Promise<void> {
    this.log('suspicious-activity', params)
  }
}
