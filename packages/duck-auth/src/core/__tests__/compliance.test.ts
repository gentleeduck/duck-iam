import { describe, expect, it } from 'vitest'
import { toPasswordsConfig } from '~/providers/password'
import { applyCompliancePreset, assertComplianceStrict, readCompliancePreset, resolveCompliance } from '../compliance'

describe('authResolveCompliance', () => {
  it('returns defaults when no preset', () => {
    const r = resolveCompliance(undefined)
    expect(r.passwords.minLength).toBe(8)
    expect(r.minAal).toBe(1)
    expect(r.requireDataAtRest).toBe(false)
  })

  it('hipaa ratchets minLength to 12 + minAal to 2 + requires dataAtRest', () => {
    const r = resolveCompliance('hipaa')
    expect(r.passwords.minLength).toBe(12)
    expect(r.minAal).toBe(2)
    expect(r.requireDataAtRest).toBe(true)
  })

  it('fips ratchets minLength to 14 + apiKeys.randomBytes to 48', () => {
    const r = resolveCompliance('fips')
    expect(r.passwords.minLength).toBe(14)
    expect(r.apiKeys.randomBytes).toBe(48)
  })

  it('layered presets take the stricter value at each field', () => {
    const r = resolveCompliance(['gdpr', 'hipaa', 'fips'])
    expect(r.passwords.minLength).toBe(14) // fips highest
    expect(r.minAal).toBe(2) // hipaa + fips both 2
    expect(r.sessions.absoluteTtlMs).toBeLessThanOrEqual(8 * 60 * 60 * 1000) // hipaa cap
    expect(r.requireDataAtRest).toBe(true)
    expect(r.requireChannelForReset).toBe(true)
  })

  it('layered presets merge requiredStrictChecks lists without duplicates', () => {
    const r = resolveCompliance(['gdpr', 'soc2'])
    expect(r.requiredStrictChecks).toContain('exportAvailable')
    expect(r.requiredStrictChecks).toContain('lockoutListener')
    // Dedup check: arrays must have unique entries.
    expect(new Set(r.requiredStrictChecks).size).toBe(r.requiredStrictChecks.length)
  })
})

describe('authApplyCompliancePreset', () => {
  it('ratchets user config to the stricter preset value', () => {
    const base = {
      baseUrl: 'x',
      transport: {} as never,
      stores: {} as never,
      session: { ttlMs: 30 * 24 * 60 * 60 * 1000 },
    }
    const ratcheted = applyCompliancePreset(base as never, 'hipaa')
    // hipaa caps session ttl to 1h
    expect(ratcheted.session?.ttlMs).toBeLessThanOrEqual(60 * 60 * 1000)
    // password compliance is provider-level now: passwordProvider({ compliance }) ratchets minLength.
    expect(toPasswordsConfig({ minLength: 6, compliance: 'hipaa' }).minLength).toBe(12)
  })

  it('does not weaken user config below the preset', () => {
    // A user value above the preset floor is kept.
    expect(toPasswordsConfig({ minLength: 20, compliance: 'hipaa' }).minLength).toBe(20)
  })
})

describe('authAssertComplianceStrict', () => {
  it('passes when every required adapter is wired', () => {
    expect(() =>
      assertComplianceStrict({
        preset: 'hipaa',
        wired: { dataAtRest: true, mailerChannel: true, auditListener: true, fipsValidatedHasher: true },
      }),
    ).not.toThrow()
  })

  it('fails with AUTH/MISCONFIGURED listing every missing requirement', () => {
    try {
      assertComplianceStrict({
        preset: 'hipaa',
        wired: { dataAtRest: false, mailerChannel: false, auditListener: false, fipsValidatedHasher: false },
      })
      expect.fail('expected throw')
    } catch (err) {
      const meta = err as { code: string; meta: { detail: string } }
      expect(meta.code).toBe('AUTH_MISCONFIGURED')
      expect(meta.meta.detail).toContain('dataAtRest')
      expect(meta.meta.detail).toContain('mailer/channel')
      expect(meta.meta.detail).toContain('audit-log listener')
    }
  })

  it('fips requires fipsValidatedHasher explicitly', () => {
    expect(() =>
      assertComplianceStrict({
        preset: 'fips',
        wired: { dataAtRest: true, mailerChannel: true, auditListener: false, fipsValidatedHasher: false },
      }),
    ).toThrow()
  })
})

describe('readCompliancePreset - SEC: brand validation', () => {
  it('returns null when cfg is not an object', () => {
    expect(readCompliancePreset(null)).toBeNull()
    expect(readCompliancePreset(undefined)).toBeNull()
    expect(readCompliancePreset('hipaa')).toBeNull()
    expect(readCompliancePreset(42)).toBeNull()
  })

  it('returns null when the __compliancePreset key is missing', () => {
    expect(readCompliancePreset({})).toBeNull()
    expect(readCompliancePreset({ other: 'value' })).toBeNull()
  })

  it('returns a valid string preset', () => {
    expect(readCompliancePreset({ __compliancePreset: 'hipaa' })).toBe('hipaa')
    expect(readCompliancePreset({ __compliancePreset: 'fips' })).toBe('fips')
  })

  it('returns a valid preset array', () => {
    expect(readCompliancePreset({ __compliancePreset: ['gdpr', 'soc2'] })).toEqual(['gdpr', 'soc2'])
  })

  it('returns null when the brand value is an unknown string (e.g. tampered)', () => {
    expect(readCompliancePreset({ __compliancePreset: 'evil-preset' })).toBeNull()
  })

  it('returns null when the brand value is a non-string (object/number)', () => {
    expect(readCompliancePreset({ __compliancePreset: { fake: true } })).toBeNull()
    expect(readCompliancePreset({ __compliancePreset: 1 })).toBeNull()
  })

  it('returns null when an array contains a non-preset entry', () => {
    expect(readCompliancePreset({ __compliancePreset: ['gdpr', 'evil-preset'] })).toBeNull()
    expect(readCompliancePreset({ __compliancePreset: ['hipaa', 42] })).toBeNull()
  })

  it('returns null on an empty array (would otherwise have run no checks under "presets")', () => {
    expect(readCompliancePreset({ __compliancePreset: [] })).toBeNull()
  })
})
