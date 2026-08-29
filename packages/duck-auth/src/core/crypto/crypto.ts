import { createHash, timingSafeEqual as nodeTimingSafeEqual, randomBytes } from 'node:crypto'

/** 32-byte random token, base64url. Used for session IDs, CSRF, magic links. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url')
}

export { v7 as authUlid } from 'uuid'

/**
 * SHA-256 hash of input, hex-encoded. Used for at-rest token storage:
 * session ids, CSRF tokens, API keys, OAuth/OIDC refresh tokens, MFA codes.
 * Every caller passes a high-entropy value already produced by `randomToken()`
 * or an equivalent generator - never a human-chosen password, which goes
 * through `Argon2idHasher`/`ScryptHasher` in providers/passwords instead. A
 * fast hash is correct here: these values can't be brute-forced by guessing
 * regardless of hash speed, and a slow KDF would make every lookup (e.g. one
 * per API request) needlessly expensive.
 */
// codeql[js/insufficient-password-hash]: false positive - hashes random tokens/API keys, not passwords; see doc comment above.
export function sha256(s: string): string {
  return createHash('sha256').update(s).digest('hex')
}

/** Constant-time string compare. Length mismatch returns false in constant time too. */
export function timingSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ab.length !== bb.length) {
    // Touch both buffers to keep the comparison constant-time across length mismatch.
    nodeTimingSafeEqual(ab, ab)
    return false
  }
  return nodeTimingSafeEqual(ab, bb)
}
