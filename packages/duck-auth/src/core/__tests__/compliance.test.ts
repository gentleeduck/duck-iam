import { describe, expect, it } from 'vitest'
import { assertComplianceStrict, readCompliancePreset, resolveCompliance } from '../compliance'

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

describe('assertComplianceStrict', () => {
  it('passes when every required adapter is wired', () => {
    expect(() =>
      assertComplianceStrict({
        preset: 'hipaa',
        wired: {
          auditLogRetained7y: true,
          baaCompliantChannel: true,
          dataAtRest: true,
          fipsValidatedHasher: true,
          mailerChannel: true,
        },
      }),
    ).not.toThrow()
  })

  it('fails with AUTH_MISCONFIGURED listing every missing requirement', () => {
    try {
      assertComplianceStrict({
        preset: 'hipaa',
        wired: {},
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
        wired: { dataAtRest: true, mailerChannel: true, webauthnAttestationDirect: true },
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

  it('refuses a brand value that is an unknown string (e.g. tampered)', () => {
    // Was null, which reported a tampered config as carrying no preset at all - so editing the
    // brand was a way to turn compliance off rather than a way to be caught doing it.
    expect(() => readCompliancePreset({ __compliancePreset: 'evil-preset' })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('refuses a brand value that is a non-string (object/number)', () => {
    for (const value of [{ fake: true }, 1]) {
      expect(() => readCompliancePreset({ __compliancePreset: value })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })

  it('refuses an array containing a non-preset entry, naming it', () => {
    // One misspelt entry in a two-preset list used to report the whole config as unbranded, so a
    // typo turned compliance off instead of narrowing it.
    const err = (() => {
      try {
        readCompliancePreset({ __compliancePreset: ['gdpr', 'evil-preset'] })
        return null
      } catch (e) {
        return e as Error & { meta: { detail: string } }
      }
    })()
    expect(err?.meta.detail).toContain('evil-preset')
    expect(() => readCompliancePreset({ __compliancePreset: ['hipaa', 42] })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('returns null on an empty array (would otherwise have run no checks under "presets")', () => {
    expect(readCompliancePreset({ __compliancePreset: [] })).toBeNull()
  })
})
