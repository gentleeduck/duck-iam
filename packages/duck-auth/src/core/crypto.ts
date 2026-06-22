import { createHash, timingSafeEqual as nodeTimingSafeEqual, randomBytes } from 'node:crypto'

/** 32-byte random token, base64url. Used for session IDs, CSRF, magic links. */
export function authRandomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url')
}

/** SHA-256 hash of input, hex-encoded. Used for at-rest token storage. */
export function authSha256(s: string): string {
  return createHash('sha256').update(s).digest('hex')
}

/** Constant-time string compare. Length mismatch returns false in constant time too. */
export function authTimingSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ab.length !== bb.length) {
    // Touch both buffers to keep the comparison constant-time across length mismatch.
    nodeTimingSafeEqual(ab, ab)
    return false
  }
  return nodeTimingSafeEqual(ab, bb)
}
