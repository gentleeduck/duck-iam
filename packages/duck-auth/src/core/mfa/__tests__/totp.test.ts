import { describe, expect, it } from 'vitest'
import { authBase32Decode, authBase32Encode, buildOtpAuthUri, authGenerateSecret, TOTP_DEFAULTS, totpAt, authVerifyTotp } from '../totp'

describe('base32', () => {
  it('roundtrip arbitrary bytes', () => {
    const original = Buffer.from([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])
    const encoded = authBase32Encode(original)
    expect(encoded).toMatch(/^[A-Z2-7]+$/)
    const decoded = authBase32Decode(encoded)
    expect(decoded.equals(original)).toBe(true)
  })

  it('decode is case-insensitive and tolerates spaces + padding', () => {
    const original = Buffer.from([0xaa, 0xbb])
    const encoded = authBase32Encode(original).toLowerCase()
    const decoded = authBase32Decode(`  ${encoded}====  `)
    expect(decoded.equals(original)).toBe(true)
  })

  it('decode rejects characters outside the alphabet', () => {
    expect(() => authBase32Decode('!@#$')).toThrow(/invalid base32/)
  })
})

describe('authGenerateSecret + buildOtpAuthUri', () => {
  it('secret is base32, 32 chars (20-byte secret)', () => {
    const s = authGenerateSecret()
    expect(s).toMatch(/^[A-Z2-7]{32}$/)
  })

  it('otpauth URI carries issuer, algorithm, digits, period, secret', () => {
    const uri = buildOtpAuthUri({ secret: 'JBSWY3DPEHPK3PXP', issuer: 'Acme', accountName: 'alice@x.com' })
    expect(uri).toMatch(/^otpauth:\/\/totp\/Acme%3Aalice%40x\.com\?/)
    const params = new URL(uri).searchParams
    expect(params.get('secret')).toBe('JBSWY3DPEHPK3PXP')
    expect(params.get('issuer')).toBe('Acme')
    expect(params.get('algorithm')).toBe('SHA1')
    expect(params.get('digits')).toBe('6')
    expect(params.get('period')).toBe('30')
  })
})

describe('totpAt', () => {
  it('RFC 6238 SHA1 test vector at counter=1', () => {
    // RFC 6238 test secret "12345678901234567890" -> base32 = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    const code = totpAt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1)
    expect(code).toBe('287082')
  })

  it('always returns the configured number of digits', () => {
    const code = totpAt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 12345)
    expect(code).toHaveLength(TOTP_DEFAULTS.digits)
    expect(code).toMatch(/^\d{6}$/)
  })
})

describe('authVerifyTotp', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
  const fixedNow = 1_700_000_000_000 // pinned for determinism
  const stepIndex = Math.floor(fixedNow / 1000 / TOTP_DEFAULTS.periodSec)

  it('accepts the code for the current step', () => {
    const code = totpAt(secret, stepIndex)
    expect(authVerifyTotp(secret, code, { nowMs: fixedNow })).toBe(true)
  })

  it('accepts ±1 step drift', () => {
    expect(authVerifyTotp(secret, totpAt(secret, stepIndex - 1), { nowMs: fixedNow })).toBe(true)
    expect(authVerifyTotp(secret, totpAt(secret, stepIndex + 1), { nowMs: fixedNow })).toBe(true)
  })

  it('rejects a code outside the drift window', () => {
    expect(authVerifyTotp(secret, totpAt(secret, stepIndex - 2), { nowMs: fixedNow })).toBe(false)
    expect(authVerifyTotp(secret, totpAt(secret, stepIndex + 2), { nowMs: fixedNow })).toBe(false)
  })

  it('rejects malformed codes without throwing', () => {
    expect(authVerifyTotp(secret, '12345', { nowMs: fixedNow })).toBe(false)
    expect(authVerifyTotp(secret, '1234567', { nowMs: fixedNow })).toBe(false)
    expect(authVerifyTotp(secret, 'abcdef', { nowMs: fixedNow })).toBe(false)
    expect(authVerifyTotp(secret, '', { nowMs: fixedNow })).toBe(false)
  })

  it('rejects with the wrong secret', () => {
    const code = totpAt(secret, stepIndex)
    expect(authVerifyTotp(authGenerateSecret(), code, { nowMs: fixedNow })).toBe(false)
  })
})
