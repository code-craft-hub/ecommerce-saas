import type { OAuthAccount } from '@/domain/auth/entities/OAuthAccount'
import type { OAuthProvider } from '@/domain/auth/value-objects/OAuthProfile'

export interface IOAuthAccountRepository {
  findByProvider(
    provider: OAuthProvider,
    providerUserId: string,
  ): Promise<OAuthAccount | null>
  findByUserId(userId: string): Promise<OAuthAccount[]>
  save(account: OAuthAccount): Promise<void>
  update(account: OAuthAccount): Promise<void>
  delete(id: string): Promise<void>
}
