import { describe, expect, it } from 'vitest'
import { base32Decode, base32Encode, buildOtpAuthUri, generateSecret, TOTP_DEFAULTS, totpAt, verifyTotp } from '../totp'

describe('base32', () => {
  it('roundtrip arbitrary bytes', () => {
    const original = Buffer.from([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])
    const encoded = base32Encode(original)
    expect(encoded).toMatch(/^[A-Z2-7]+$/)
    const decoded = base32Decode(encoded)
    expect(decoded.equals(original)).toBe(true)
  })

  it('decode is case-insensitive and tolerates spaces + padding', () => {
    const original = Buffer.from([0xaa, 0xbb])
    const encoded = base32Encode(original).toLowerCase()
    const decoded = base32Decode(`  ${encoded}====  `)
    expect(decoded.equals(original)).toBe(true)
  })

  it('decode rejects characters outside the alphabet', () => {
    expect(() => base32Decode('!@#$')).toThrow(/invalid base32/)
  })
})

describe('generateSecret + buildOtpAuthUri', () => {
  it('secret is base32, 32 chars (20-byte secret)', () => {
    const s = generateSecret()
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
    // RFC 6238 test secret "12345678901234567890" → base32 = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    const code = totpAt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1)
    expect(code).toBe('287082')
  })

  it('always returns the configured number of digits', () => {
    const code = totpAt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 12345)
    expect(code).toHaveLength(TOTP_DEFAULTS.digits)
    expect(code).toMatch(/^\d{6}$/)
  })
})

describe('verifyTotp', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
  const fixedNow = 1_700_000_000_000 // pinned for determinism
  const stepIndex = Math.floor(fixedNow / 1000 / TOTP_DEFAULTS.periodSec)

  it('accepts the code for the current step', () => {
    const code = totpAt(secret, stepIndex)
    expect(verifyTotp(secret, code, { nowMs: fixedNow })).toBe(true)
  })

  it('accepts ±1 step drift', () => {
    expect(verifyTotp(secret, totpAt(secret, stepIndex - 1), { nowMs: fixedNow })).toBe(true)
    expect(verifyTotp(secret, totpAt(secret, stepIndex + 1), { nowMs: fixedNow })).toBe(true)
  })

  it('rejects a code outside the drift window', () => {
    expect(verifyTotp(secret, totpAt(secret, stepIndex - 2), { nowMs: fixedNow })).toBe(false)
    expect(verifyTotp(secret, totpAt(secret, stepIndex + 2), { nowMs: fixedNow })).toBe(false)
  })

  it('rejects malformed codes without throwing', () => {
    expect(verifyTotp(secret, '12345', { nowMs: fixedNow })).toBe(false)
    expect(verifyTotp(secret, '1234567', { nowMs: fixedNow })).toBe(false)
    expect(verifyTotp(secret, 'abcdef', { nowMs: fixedNow })).toBe(false)
    expect(verifyTotp(secret, '', { nowMs: fixedNow })).toBe(false)
  })

  it('rejects with the wrong secret', () => {
    const code = totpAt(secret, stepIndex)
    expect(verifyTotp(generateSecret(), code, { nowMs: fixedNow })).toBe(false)
  })
})
