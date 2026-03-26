import type { HashedPassword } from '@/domain/auth/value-objects/Password'
import type { PlaintextPassword } from '@/domain/auth/value-objects/Password'

/**
 * Port (interface) for password hashing.
 * Infrastructure adapter: Argon2PasswordHasher implements this.
 */
export interface IPasswordHashingService {
  /** Hash a plaintext password with Argon2id + pepper */
  hash(
    password: PlaintextPassword,
    pepperVersion: number,
  ): Promise<HashedPassword>

  /** Verify plaintext against stored hash, applying correct pepper version */
  verify(
    password: PlaintextPassword,
    hash: HashedPassword,
    pepperVersion: number,
  ): Promise<boolean>

  /** Current pepper version (for rotation tracking) */
  currentPepperVersion: number
}
