import { createHash, timingSafeEqual as nodeTimingSafeEqual, randomBytes, randomFillSync } from 'node:crypto'

/** base64url, so the value is URL- and cookie-safe as it stands. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url')
}

const v7 = { bytes: Buffer.alloc(16), msecs: Number.NEGATIVE_INFINITY, seq: 0 }

/**
 * UUIDv7 (RFC 9562): 48-bit unix ms, a 32-bit counter seeded at random each new ms, then random bits.
 * NOTE: ids keep creation order inside one process, even within a millisecond or when the clock steps back.
 */
export function authUuidV7(): string {
  const bytes = randomFillSync(v7.bytes)
  const now = Date.now()
  if (now > v7.msecs) {
    v7.seq = bytes.readUInt32BE(6) & 0x7fffffff
    v7.msecs = now
  } else {
    v7.seq = (v7.seq + 1) | 0
    if (v7.seq === 0) v7.msecs++
  }
  const seq = v7.seq >>> 0
  bytes.writeUIntBE(v7.msecs, 0, 6)
  bytes.writeUInt8(0x70 | ((seq >>> 28) & 0x0f), 6)
  bytes.writeUInt8((seq >>> 20) & 0xff, 7)
  bytes.writeUInt8(0x80 | ((seq >>> 14) & 0x3f), 8)
  bytes.writeUInt8((seq >>> 6) & 0xff, 9)
  bytes.writeUInt8(((seq << 2) & 0xfc) | (bytes.readUInt8(10) & 0x03), 10)
  const hex = bytes.toString('hex')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

/**
 * At-rest storage for session ids, CSRF tokens, API keys, refresh tokens and MFA codes.
 *
 * SECURITY: every caller passes a high-entropy value from {@link randomToken} or the like, never a
 * human-chosen password, which goes through `Argon2idHasher`/`ScryptHasher` instead. A fast hash is
 * right here: guessing cannot brute-force these whatever the hash costs, and a slow KDF would price
 * every lookup, one per API request among them.
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
