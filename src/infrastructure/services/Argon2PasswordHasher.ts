import { hash, verify } from '@node-rs/argon2'
import type { IPasswordHashingService } from '@/domain/auth/services/IPasswordHashingService'
import type {
  HashedPassword,
  PlaintextPassword,
} from '@/domain/auth/value-objects/Password'
import { HashedPassword as HashedPasswordVO } from '@/domain/auth/value-objects/Password'

/**
 * Argon2id password hasher — OWASP PHC winner.
 *
 * Parameters per OWASP 2023 recommendations:
 * - Algorithm: Argon2id (hybrid, protects against side-channel + GPU attacks)
 * - Memory: 19 MiB (19456 KiB) — minimum OWASP recommendation
 * - Iterations: 2
 * - Parallelism: 1
 * - Salt: 16 bytes random (handled by @node-rs/argon2 automatically)
 *
 * Pepper: additional secret appended to password before hashing.
 * Stored in environment, not the database — prevents offline dictionary attacks
 * if the DB is compromised without the application server.
 */
export class Argon2PasswordHasher implements IPasswordHashingService {
  private readonly peppers: Map<number, string>

  constructor(peppers: Record<number, string>) {
    this.peppers = new Map(Object.entries(peppers).map(([k, v]) => [Number(k), v]))
    if (this.peppers.size === 0) {
      throw new Error('At least one pepper must be configured')
    }
  }

  get currentPepperVersion(): number {
    return Math.max(...this.peppers.keys())
  }

  async hash(
    password: PlaintextPassword,
    pepperVersion: number,
  ): Promise<HashedPassword> {
    const pepper = this.getPepper(pepperVersion)
    const pepperedPassword = password.value + pepper

    const hashStr = await hash(pepperedPassword, {
      algorithm: 2, // Argon2id
      memoryCost: 19456, // 19 MiB
      timeCost: 2, // iterations
      parallelism: 1,
    })

    return HashedPasswordVO.fromHash(hashStr)
  }

  async verify(
    password: PlaintextPassword,
    storedHash: HashedPassword,
    pepperVersion: number,
  ): Promise<boolean> {
    const pepper = this.getPepper(pepperVersion)
    const pepperedPassword = password.value + pepper

    try {
      return await verify(storedHash.hash, pepperedPassword)
    } catch {
      return false
    }
  }

  private getPepper(version: number): string {
    const pepper = this.peppers.get(version)
    if (!pepper) {
      throw new Error(`Unknown pepper version: ${version}`)
    }
    return pepper
  }
}
