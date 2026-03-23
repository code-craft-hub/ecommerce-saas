/**
 * Shared token utilities — safe for use in Node.js runtime.
 * All cryptographic operations use the Web Crypto API (available in Node 16+).
 */

/**
 * SHA-256 hash a token for safe storage.
 * NEVER store refresh tokens in plaintext.
 */
export async function hashToken(token: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return bufferToHex(hashBuffer)
}

/**
 * Generate a cryptographically secure opaque refresh token.
 * 256 bits of entropy — unguessable.
 */
export function generateOpaqueToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return bufferToHex(bytes.buffer)
}

function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Timing-safe string comparison to prevent timing attacks.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  const encoder = new TextEncoder()
  const aBytes = encoder.encode(a)
  const bBytes = encoder.encode(b)
  let diff = 0
  for (let i = 0; i < aBytes.length; i++) {
    diff |= aBytes[i] ^ bBytes[i]
  }
  return diff === 0
}
