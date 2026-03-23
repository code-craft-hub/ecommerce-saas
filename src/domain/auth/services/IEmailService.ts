/**
 * Port for transactional email service.
 * Adapters: SendGrid, SES, Resend, Nodemailer, etc.
 */
export interface IEmailService {
  sendVerificationEmail(params: {
    to: string
    name: string
    verificationUrl: string
  }): Promise<void>

  sendPasswordResetEmail(params: {
    to: string
    name: string
    resetUrl: string
    expiresInMinutes: number
  }): Promise<void>

  sendPasswordChangedNotification(params: {
    to: string
    name: string
    ipAddress: string | null
    timestamp: Date
  }): Promise<void>

  sendNewOAuthLinkNotification(params: {
    to: string
    name: string
    provider: string
    providerEmail: string
  }): Promise<void>

  sendSuspiciousActivityAlert(params: {
    to: string
    name: string
    ipAddress: string | null
    userAgent: string | null
    timestamp: Date
  }): Promise<void>
}
