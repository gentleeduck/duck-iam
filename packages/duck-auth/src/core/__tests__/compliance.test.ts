/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { describe, expect, it } from 'vitest'
import { applyCompliancePreset, assertComplianceStrict, resolveCompliance } from '../compliance'

describe('resolveCompliance', () => {
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

describe('applyCompliancePreset', () => {
  it('ratchets user config to the stricter preset value', () => {
    const base = {
      baseUrl: 'x',
      transport: {} as never,
      stores: {} as never,
      passwords: { minLength: 6 },
      session: { ttlMs: 30 * 24 * 60 * 60 * 1000 },
    }
    const ratcheted = applyCompliancePreset(base as never, 'hipaa')
    expect(ratcheted.passwords?.minLength).toBe(12)
    // hipaa caps session ttl to 1h
    expect(ratcheted.session?.ttlMs).toBeLessThanOrEqual(60 * 60 * 1000)
  })

  it('does not weaken user config below the preset', () => {
    const base = {
      baseUrl: 'x',
      transport: {} as never,
      stores: {} as never,
      passwords: { minLength: 20 },
    }
    const ratcheted = applyCompliancePreset(base as never, 'hipaa')
    expect(ratcheted.passwords?.minLength).toBe(20)
  })
})

describe('assertComplianceStrict', () => {
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
      expect(meta.code).toBe('AUTH/MISCONFIGURED')
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
