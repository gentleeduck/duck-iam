/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

/**
 * RFC 6238 TOTP-SHA1 with the standard 6-digit / 30-second window. The most
 * widely-supported configuration on third-party authenticator apps
 * (1Password, Bitwarden, Authy, Google Authenticator, Authenticator-app
 * on iOS / Android), so v0.1 fixes this set; HOTP / SHA-256 land later as
 * generic options if a consumer needs them.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface TotpParams {
  digits: 6
  periodSec: 30
  algorithm: 'sha1'
  /** Acceptable drift windows on either side of the current step. */
  driftSteps: number
}

export const TOTP_DEFAULTS: TotpParams = {
  digits: 6,
  periodSec: 30,
  algorithm: 'sha1',
  driftSteps: 1,
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** Encode bytes as RFC 4648 base32 (no padding). */
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

/** Decode RFC 4648 base32 (case-insensitive, ignores padding + spaces). */
export function base32Decode(s: string): Buffer {
  const cleaned = s.toUpperCase().replace(/[\s=]/g, '')
  let bits = 0
  let value = 0
  const out: number[] = []
  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i] as string
    const idx = BASE32_ALPHABET.indexOf(ch)
    if (idx < 0) throw new Error(`invalid base32 character: ${ch}`)
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((value >>> bits) & 0xff)
    }
  }
  return Buffer.from(out)
}

/** Generate a fresh 20-byte secret base32-encoded for storage + QR. */
export function generateSecret(): string {
  return base32Encode(randomBytes(20))
}

/** Build an otpauth:// URI suitable for QR generation by the consumer. */
export function buildOtpAuthUri(opts: {
  secret: string
  issuer: string
  accountName: string
  params?: Partial<TotpParams>
}): string {
  const p = { ...TOTP_DEFAULTS, ...opts.params }
  const label = encodeURIComponent(`${opts.issuer}:${opts.accountName}`)
  const issuer = encodeURIComponent(opts.issuer)
  const sp = new URLSearchParams({
    secret: opts.secret,
    issuer,
    algorithm: p.algorithm.toUpperCase(),
    digits: String(p.digits),
    period: String(p.periodSec),
  })
  return `otpauth://totp/${label}?${sp.toString()}`
}

/**
 * Compute the TOTP code at the given step. Hot path; constant-time-safe
 * comparison happens in {@link verifyTotp}.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function totpAt(secretB32: string, stepIndex: number, params: TotpParams = TOTP_DEFAULTS): string {
  const secret = base32Decode(secretB32)
  const buf = Buffer.alloc(8)
  // RFC 4226 section 5.3 - 8-byte big-endian counter.
  buf.writeBigUInt64BE(BigInt(stepIndex))
  const hmac = createHmac(params.algorithm, secret).update(buf).digest()
  const off = hmac[hmac.length - 1]! & 0x0f
  const binCode =
    ((hmac[off]! & 0x7f) << 24) |
    ((hmac[off + 1]! & 0xff) << 16) |
    ((hmac[off + 2]! & 0xff) << 8) |
    (hmac[off + 3]! & 0xff)
  const mod = 10 ** params.digits
  return (binCode % mod).toString().padStart(params.digits, '0')
}

/**
 * Verify a code against the configured drift window. Constant-time across
 * all candidate steps so an attacker cannot infer where in the window the
 * legitimate code lives by timing the response.
 *
 * `nowMs` defaults to `Date.now()`; tests pass it explicitly for determinism.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function verifyTotp(
  secretB32: string,
  code: string,
  opts: { params?: TotpParams; nowMs?: number } = {},
): boolean {
  const params = opts.params ?? TOTP_DEFAULTS
  const nowMs = opts.nowMs ?? Date.now()
  if (code.length !== params.digits) return false
  if (!/^\d+$/.test(code)) return false

  const currentStep = Math.floor(nowMs / 1000 / params.periodSec)
  const candidates: string[] = []
  for (let d = -params.driftSteps; d <= params.driftSteps; d++) {
    candidates.push(totpAt(secretB32, currentStep + d, params))
  }
  // Constant-time comparison across the whole window - never short-circuit.
  let matched = false
  for (const candidate of candidates) {
    const a = Buffer.from(candidate)
    const b = Buffer.from(code)
    if (a.length === b.length && timingSafeEqual(a, b)) matched = true
  }
  return matched
}
