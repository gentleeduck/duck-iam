import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { AuthError } from '~/core/errors'

/** TOTP parameters, per RFC 6238. */
export namespace Totp {
  export type Params = {
    digits: 6
    /** Pinned at 30s, which is what every authenticator app assumes. */
    periodSec: 30
    algorithm: 'sha1'
    /** Acceptable drift windows on either side of the current step. */
    driftSteps: number
  }
}

/** RFC 6238 defaults: six digits, thirty-second steps, one step of drift either way. */
export const TOTP_DEFAULTS: Totp.Params = {
  digits: 6,
  periodSec: 30,
  algorithm: 'sha1',
  driftSteps: 1,
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** RFC 4648 base32, unpadded. */
export function base32Encode(buf: Buffer): string {
  let bits = 0
  let value = 0
  let out = ''
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i]
    if (byte === undefined) continue
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += BASE32_ALPHABET[(value >>> bits) & 0x1f]
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f]
  return out
}

/** RFC 4648 base32, case-insensitive and ignoring padding and spaces. */
export function base32Decode(s: string): Buffer {
  const cleaned = s.toUpperCase().replace(/[\s=]/g, '')
  let bits = 0
  let value = 0
  const out: number[] = []
  // for-of yields `string` rather than `string | undefined`, so no index cast is needed.
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch)
    // NOTE: the character is not named, being a character of the shared secret.
    if (idx < 0) throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'invalid base32 character' })
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((value >>> bits) & 0xff)
    }
  }
  return Buffer.from(out)
}

/** A fresh 20-byte secret, base32-encoded for storage and the QR code. */
export function generateSecret(): string {
  return base32Encode(randomBytes(20))
}

/** An `otpauth://` URI for the consumer to render as a QR code. */
export function buildOtpAuthUri(opts: {
  secret: string
  issuer: string
  accountName: string
  params?: Partial<Totp.Params>
}): string {
  const p = { ...TOTP_DEFAULTS, ...opts.params }
  const label = encodeURIComponent(`${opts.issuer}:${opts.accountName}`)
  const sp = new URLSearchParams({
    secret: opts.secret,
    // Raw, because `URLSearchParams.toString()` percent-encodes: pre-encoding left `Acme Corp` as
    // `issuer=Acme%2520Corp` and the authenticator app displayed the escape. The label above is
    // interpolated into the path by hand, which is why that one does need encoding of its own.
    issuer: opts.issuer,
    algorithm: p.algorithm.toUpperCase(),
    digits: String(p.digits),
    period: String(p.periodSec),
  })
  return `otpauth://totp/${label}?${sp.toString()}`
}

/** The hot path; the constant-time comparison happens in {@link verifyTotp}. */
export function totpAt(secretB32: string, stepIndex: number, params: Totp.Params = TOTP_DEFAULTS): string {
  const secret = base32Decode(secretB32)
  const buf = Buffer.alloc(8)
  // RFC 4226 section 5.3: an 8-byte big-endian counter.
  buf.writeBigUInt64BE(BigInt(stepIndex))
  const hmac = createHmac(params.algorithm, secret).update(buf).digest()
  // Dynamic truncation per RFC 4226 section 5.3: the last byte's low nibble picks a 4-byte offset,
  // and `readUInt32BE` yields the truncated code with no per-byte `!` assertions.
  const off = hmac.readUInt8(hmac.length - 1) & 0x0f
  const binCode = hmac.readUInt32BE(off) & 0x7fffffff
  const mod = 10 ** params.digits
  return (binCode % mod).toString().padStart(params.digits, '0')
}

/** Whether a secret decodes to usable key material. A verification path reads its secret from storage,
 *  and a row corrupted there can verify nothing, so it is refused the way any unusable row is rather
 *  than throwing a raw Error out of whatever HTTP handler asked.
 *
 *  SECURITY: zero bytes is refused, not only input that fails to decode. Node builds a working HMAC
 *  from an empty key, so a blanked or all-padding secret produced codes derivable from the clock alone
 *  while `hasTotp` went on reporting the account protected. */
function usableSecret(secretB32: string): boolean {
  try {
    return base32Decode(secretB32).length > 0
  } catch {
    return false
  }
}

/**
 * Constant-time across every candidate step, so the response cannot be timed to find where in the drift
 * window the legitimate code lives.
 */
export function verifyTotp(
  secretB32: string,
  code: string,
  opts: { params?: Totp.Params; nowMs?: number } = {},
): boolean {
  const params = opts.params ?? TOTP_DEFAULTS
  const nowMs = opts.nowMs ?? Date.now()
  if (code.length !== params.digits) return false
  if (!/^\d+$/.test(code)) return false
  if (!usableSecret(secretB32)) return false

  const currentStep = Math.floor(nowMs / 1000 / params.periodSec)
  const candidates: string[] = []
  for (let d = -params.driftSteps; d <= params.driftSteps; d++) {
    candidates.push(totpAt(secretB32, currentStep + d, params))
  }
  // Constant-time across the whole window, never short-circuiting.
  let matched = false
  for (const candidate of candidates) {
    const a = Buffer.from(candidate)
    const b = Buffer.from(code)
    if (a.length === b.length && timingSafeEqual(a, b)) matched = true
  }
  return matched
}

/** Which time step a code matches, or `null` when none in the drift window does. */
export function matchTotpStep(
  secretB32: string,
  code: string,
  opts: { params?: Totp.Params; nowMs?: number } = {},
): number | null {
  const params = opts.params ?? TOTP_DEFAULTS
  const nowMs = opts.nowMs ?? Date.now()
  if (code.length !== params.digits) return null
  if (!/^\d+$/.test(code)) return null
  if (!usableSecret(secretB32)) return null

  const currentStep = Math.floor(nowMs / 1000 / params.periodSec)
  let matchedStep: number | null = null
  for (let d = -params.driftSteps; d <= params.driftSteps; d++) {
    const step = currentStep + d
    const a = Buffer.from(totpAt(secretB32, step, params))
    const b = Buffer.from(code)
    if (a.length === b.length && timingSafeEqual(a, b)) matchedStep = step
  }
  return matchedStep
}
