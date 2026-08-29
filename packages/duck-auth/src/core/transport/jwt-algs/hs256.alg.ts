/** HS256: HMAC-SHA256 sign + constant-time verify. */
import { createHmac, timingSafeEqual } from 'node:crypto'

// codeql[js/insufficient-password-hash]: false positive - this is HMAC-SHA256 JWT signing (RFC 7518 HS256), not password hashing; `key` is the JWT signing secret, `signingInput` is the token payload being signed, neither is a stored password.
export function signHs256(key: string, signingInput: string): string {
  return createHmac('sha256', key).update(signingInput).digest('base64url')
}

export function verifyHs256(key: string, signingInput: string, sigB64: string): boolean {
  const expected = signHs256(key, signingInput)
  const a = Buffer.from(sigB64)
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}
