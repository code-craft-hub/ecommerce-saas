/**
 * RefreshToken entity — opaque token stored server-side.
 * Implements rotation family tracking for breach detection.
 */
export interface RefreshTokenProps {
  id: string
  userId: string
  /** SHA-256 hash of the actual token — NEVER store plaintext */
  tokenHash: string
  rotationFamilyId: string
  issuedAt: Date
  expiresAt: Date
  revokedAt: Date | null
  rotatedAt: Date | null
  usedAt: Date | null
  deviceId: string | null
  ipAddress: string | null
  userAgentHash: string | null
}

export class RefreshToken {
  private constructor(private props: RefreshTokenProps) {}

  static reconstitute(props: RefreshTokenProps): RefreshToken {
    return new RefreshToken(props)
  }

  static create(params: {
    id: string
    userId: string
    tokenHash: string
    rotationFamilyId: string
    expiresAt: Date
    deviceId?: string | null
    ipAddress?: string | null
    userAgentHash?: string | null
  }): RefreshToken {
    return new RefreshToken({
      id: params.id,
      userId: params.userId,
      tokenHash: params.tokenHash,
      rotationFamilyId: params.rotationFamilyId,
      issuedAt: new Date(),
      expiresAt: params.expiresAt,
      revokedAt: null,
      rotatedAt: null,
      usedAt: null,
      deviceId: params.deviceId ?? null,
      ipAddress: params.ipAddress ?? null,
      userAgentHash: params.userAgentHash ?? null,
    })
  }

  get id(): string {
    return this.props.id
  }
  get userId(): string {
    return this.props.userId
  }
  get tokenHash(): string {
    return this.props.tokenHash
  }
  get rotationFamilyId(): string {
    return this.props.rotationFamilyId
  }
  get issuedAt(): Date {
    return this.props.issuedAt
  }
  get expiresAt(): Date {
    return this.props.expiresAt
  }
  get revokedAt(): Date | null {
    return this.props.revokedAt
  }
  get rotatedAt(): Date | null {
    return this.props.rotatedAt
  }
  get usedAt(): Date | null {
    return this.props.usedAt
  }
  get deviceId(): string | null {
    return this.props.deviceId
  }
  get ipAddress(): string | null {
    return this.props.ipAddress
  }
  get userAgentHash(): string | null {
    return this.props.userAgentHash
  }

  get isValid(): boolean {
    return (
      !this.isExpired &&
      this.props.revokedAt === null &&
      this.props.rotatedAt === null
    )
  }

  get isExpired(): boolean {
    return this.props.expiresAt < new Date()
  }

  markUsed(): void {
    this.props.usedAt = new Date()
  }

  rotate(): void {
    this.props.rotatedAt = new Date()
  }

  revoke(): void {
    this.props.revokedAt = new Date()
  }
}
