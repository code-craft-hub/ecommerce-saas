import type { RefreshToken } from '@/domain/auth/entities/RefreshToken'

export interface IRefreshTokenRepository {
  findByHash(tokenHash: string): Promise<RefreshToken | null>
  findById(id: string): Promise<RefreshToken | null>
  findActiveByUserId(userId: string): Promise<RefreshToken[]>
  save(token: RefreshToken): Promise<void>
  update(token: RefreshToken): Promise<void>
  /** Revoke all tokens for a user (used during logout-all / password change) */
  revokeAllForUser(userId: string): Promise<number>
  /** Revoke all tokens in a rotation family (breach detection) */
  revokeFamilyTokens(familyId: string): Promise<void>
  /** Count active sessions for a user */
  countActiveForUser(userId: string): Promise<number>
  /** Clean up expired tokens (for maintenance jobs) */
  deleteExpired(): Promise<number>
}
