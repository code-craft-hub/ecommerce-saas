import type { User } from '@/domain/auth/entities/User'

export interface IUserRepository {
  findById(id: string): Promise<User | null>
  findByEmail(email: string): Promise<User | null>
  save(user: User): Promise<void>
  /** Upsert — create or update based on entity state */
  update(user: User): Promise<void>
  /** Soft-delete by setting deletedAt */
  delete(id: string): Promise<void>
}
