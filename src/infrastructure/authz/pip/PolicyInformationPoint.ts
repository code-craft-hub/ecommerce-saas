/**
 * PolicyInformationPoint (PIP).
 *
 * Fetches contextual attributes required for policy evaluation that are not
 * available in the JWT or request itself:
 *   - IP reputation (Redis-cached threat intelligence)
 *   - Recent failed login count for a user (Redis counter)
 *   - Subject's current roles (database)
 *
 * The PIP caches aggressively to keep PDP latency under 10ms (from Redis).
 */

import type { IUserRoleRepository } from '@/domain/authz/repositories/IUserRoleRepository'
import type { IpReputation } from '@/domain/authz/value-objects/AuthorizationContext'

export interface EnrichedEnvironment {
  ipReputation: IpReputation
  recentFailedLogins: number
  roles: string[]
}

export class PolicyInformationPoint {
  constructor(
    private readonly userRoleRepo: IUserRoleRepository,
    private readonly redisClient: {
      get(key: string): Promise<string | null>
    },
  ) {}

  /**
   * Enrich an authorization context with runtime attributes.
   * Called by PEP before invoking PDP.
   */
  async enrich(userId: string, ipAddress: string | null): Promise<EnrichedEnvironment> {
    const [roleAssignments, ipRep, failedLogins] = await Promise.all([
      this.userRoleRepo.findRolesForUser(userId),
      this.getIpReputation(ipAddress),
      this.getRecentFailedLogins(userId),
    ])

    const roles = roleAssignments.map((a) => a.roleName)
    if (roles.length === 0) roles.push('user') // default role

    return {
      ipReputation: ipRep,
      recentFailedLogins: failedLogins,
      roles,
    }
  }

  private async getIpReputation(ipAddress: string | null): Promise<IpReputation> {
    if (!ipAddress) return 'unknown'
    try {
      const cached = await this.redisClient.get(`ip:rep:${ipAddress}`)
      if (!cached) return 'unknown'
      const valid: IpReputation[] = ['clean', 'suspicious', 'blocked', 'unknown']
      return valid.includes(cached as IpReputation)
        ? (cached as IpReputation)
        : 'unknown'
    } catch {
      return 'unknown'
    }
  }

  private async getRecentFailedLogins(userId: string): Promise<number> {
    try {
      const key = `auth:failed:${userId}`
      const val = await this.redisClient.get(key)
      return val ? parseInt(val, 10) : 0
    } catch {
      return 0
    }
  }
}
