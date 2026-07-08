/** HS256: HMAC-SHA256 sign + constant-time verify. */
import { createHmac, timingSafeEqual } from 'node:crypto'

export function signHs256(key: string, signingInput: string): string {
  return createHmac('sha256', key).update(signingInput).digest('base64url')
}

export function verifyHs256(key: string, signingInput: string, sigB64: string): boolean {
  const expected = signHs256(key, signingInput)
  const a = Buffer.from(sigB64)
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}
