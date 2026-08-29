/**
 * A compliance preset is a promise: name `hipaa` and the wiring that a HIPAA
 * deployment needs is enforced for you. What makes that promise dangerous is
 * that it is silent when it is not kept, so these cases ask, for each field a
 * preset resolves, whether anything in the library actually reads it.
 *
 * The existing suite covers the resolver's arithmetic and the brand validation.
 * These cover the gap between what a preset declares and what is enforced, plus
 * the mutability of the objects the resolver hands back.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { applyCompliancePreset, assertComplianceStrict, readCompliancePreset, resolveCompliance } from '../compliance'
import type { Compliance } from '../compliance.types'

const baseCfg = () => {
  const adapter = new MemoryAdapter()
  return {
    adapter,
    cfg: {
      baseUrl: 'https://app.test',
      limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
      providers: [],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'sid', secure: true }),
    },
  }
}

describe('what a preset declares against what is enforced', () => {
  it('FINDING: nothing in the library reads the preset a config was branded with', () => {
    // `readCompliancePreset` is documented as the hook `AuthEngine.strict()` uses
    // to "auto-invoke authAssertComplianceStrict so operators do not have to
    // remember the second call". No caller exists. An operator who follows the
    // doc, brands the config and calls `strict()`, gets none of the compliance
    // assertions and no warning that they were skipped.
    const { cfg } = baseCfg()
    const branded = applyCompliancePreset(cfg as never, 'hipaa')
    expect(readCompliancePreset(branded)).toBe('hipaa')

    // The engine builds and `strict()` passes despite hipaa requiring a
    // dataAtRest adapter and an audit listener, neither of which is wired.
    const engine = new AuthEngine(branded as never)
    expect(() => engine.strict({ idempotency: true } as never)).not.toThrow()
  })

  it('FINDING: minAal is resolved by every preset and consumed by nothing', () => {
    // `hipaa` and `fips` both declare `minAal: 2`, which reads as "every session
    // this deployment creates must be at least AAL 2". The field is computed,
    // merged and returned, and no code path anywhere compares a session's aal
    // against it, so a single-factor password sign-in under hipaa produces an
    // AAL 1 session exactly as it would with no preset at all.
    expect(resolveCompliance('hipaa').minAal).toBe(2)
    expect(resolveCompliance('fips').minAal).toBe(2)
  })

  it('FINDING: most of requiredStrictChecks is a list of strings nothing asserts', () => {
    // `assertComplianceStrict` knows four requirements. The presets between them
    // name nine. Everything outside the four is declared and never checked, so
    // `soc2` promises a lockout listener and a limiter, `gdpr` promises export and
    // soft delete, and none of those is looked at.
    const asserted = ['auditLogRetained7y', 'fipsValidatedHasher']
    const declared = new Set([
      ...resolveCompliance('gdpr').requiredStrictChecks,
      ...resolveCompliance('hipaa').requiredStrictChecks,
      ...resolveCompliance('soc2').requiredStrictChecks,
      ...resolveCompliance('fips').requiredStrictChecks,
    ])
    const unchecked = [...declared].filter((c) => !asserted.includes(c)).sort()
    expect(unchecked).toEqual([
      'baaCompliantChannel',
      'dataAtRest',
      'exportAvailable',
      'limiterRequired',
      'lockoutListener',
      'softDeleteEnabled',
      'webauthnAttestationDirect',
    ])
  })

  it('FINDING: soc2 passes the strict assertion with nothing wired but an audit listener', () => {
    // Its other two requirements are among the unchecked names, so a deployment
    // that satisfies one of three is told it satisfies soc2.
    expect(() =>
      assertComplianceStrict({
        preset: 'soc2',
        wired: { auditListener: true, dataAtRest: false, fipsValidatedHasher: false, mailerChannel: false },
      }),
    ).not.toThrow()
  })

  it('FINDING: gdpr passes without export or soft delete, the two things it names', () => {
    expect(() =>
      assertComplianceStrict({
        preset: 'gdpr',
        wired: { auditListener: false, dataAtRest: true, fipsValidatedHasher: false, mailerChannel: true },
      }),
    ).not.toThrow()
  })

  it('reports every gap it does know about in one error', () => {
    const err = (() => {
      try {
        assertComplianceStrict({
          preset: 'hipaa',
          wired: { auditListener: false, dataAtRest: false, fipsValidatedHasher: false, mailerChannel: false },
        })
        return null
      } catch (e) {
        return e as Error
      }
    })()
    expect(err?.message).toBe('AUTH_MISCONFIGURED')
    const detail = (err as unknown as { meta: { detail: string } }).meta.detail
    expect(detail).toContain('dataAtRest')
    expect(detail).toContain('mailer/channel')
    expect(detail).toContain('audit-log listener')
  })

  it('fips demands its validated hasher explicitly', () => {
    expect(() =>
      assertComplianceStrict({
        preset: 'fips',
        wired: { auditListener: true, dataAtRest: true, fipsValidatedHasher: false, mailerChannel: true },
      }),
    ).toThrow()
  })
})

describe('the resolved overrides are shared, mutable objects', () => {
  it('FINDING: resolving with no preset hands back the module’s own default object', () => {
    // The no-preset branch returns `DEFAULT_OVERRIDES` by reference. A caller that
    // adjusts what it believes is its own copy edits the module singleton, and
    // every later resolution in the process sees the change.
    const first = resolveCompliance(undefined)
    first.passwords.minLength = 99
    expect(resolveCompliance(undefined).passwords.minLength).toBe(99)
    first.passwords.minLength = 8
  })

  it('FINDING: that same object is aliased inside the gdpr and soc2 presets', () => {
    // Both spread `DEFAULT_OVERRIDES`, which copies the top level but shares every
    // nested object. Mutating the default therefore rewrites two presets, and the
    // ratchet a provider applies moves with it.
    const shared = resolveCompliance(undefined)
    shared.apiKeys.randomBytes = 1
    expect(resolveCompliance('gdpr').apiKeys.randomBytes).toBe(1)
    expect(resolveCompliance('soc2').apiKeys.randomBytes).toBe(1)
    shared.apiKeys.randomBytes = 32
  })

  it('a named preset resolves to fresh objects that do not alias the defaults', () => {
    const hipaa = resolveCompliance('hipaa')
    hipaa.passwords.minLength = 999
    expect(resolveCompliance('hipaa').passwords.minLength).toBe(12)
  })

  it('an empty array resolves to the defaults through the merge path', () => {
    expect(resolveCompliance([]).passwords.minLength).toBe(8)
    expect(resolveCompliance([]).requiredStrictChecks).toEqual([])
  })

  it('layering takes the stricter side of every field', () => {
    const both = resolveCompliance(['hipaa', 'fips'])
    expect(both.passwords.minLength).toBe(14)
    expect(both.apiKeys.randomBytes).toBe(48)
    expect(both.sessions.ttlMs).toBe(60 * 60 * 1000)
    expect(both.sessions.absoluteTtlMs).toBe(8 * 60 * 60 * 1000)
    expect(both.minAal).toBe(2)
  })

  it('FINDING: layering is order independent for every field except the check list', () => {
    // The numeric fields all come from a min or a max, so order cannot matter.
    // `requiredStrictChecks` is a set built by concatenation, so it comes back in
    // whichever order the presets were listed. Anything that fingerprints a
    // resolved policy, a config hash or a snapshot, sees two different values for
    // the same deployment.
    const ab = resolveCompliance(['hipaa', 'fips'])
    const ba = resolveCompliance(['fips', 'hipaa'])
    expect({ ...ab, requiredStrictChecks: [] }).toEqual({ ...ba, requiredStrictChecks: [] })
    expect(ab.requiredStrictChecks).not.toEqual(ba.requiredStrictChecks)
    expect([...ab.requiredStrictChecks].sort()).toEqual([...ba.requiredStrictChecks].sort())
  })

  it('layering a preset with itself changes nothing', () => {
    expect(resolveCompliance(['hipaa', 'hipaa'])).toEqual(resolveCompliance('hipaa'))
  })

  it('FINDING: an unknown preset name crashes with a TypeError instead of a misconfiguration error', () => {
    // The preset union is enforced only by TypeScript. A name arriving from a
    // config file or an environment variable indexes `PRESETS` to undefined, and
    // the merge dereferences it. Every other misconfiguration in this library is
    // an AUTH_MISCONFIGURED with a detail an operator can read.
    expect(() => resolveCompliance('hippa' as Compliance.Preset)).toThrow(TypeError)
  })
})

describe('applying a preset to an engine config', () => {
  it('ratchets the session windows down and leaves the rest of the config alone', () => {
    const { cfg } = baseCfg()
    const out = applyCompliancePreset(
      { ...cfg, session: { absoluteTtlMs: 999 * 60 * 60 * 1000, ttlMs: 999 * 60 * 60 * 1000 } } as never,
      'hipaa',
    )
    expect(out.session?.ttlMs).toBe(60 * 60 * 1000)
    expect(out.session?.absoluteTtlMs).toBe(8 * 60 * 60 * 1000)
    expect(out.baseUrl).toBe('https://app.test')
  })

  it('never lengthens a window the operator already set shorter', () => {
    const { cfg } = baseCfg()
    const out = applyCompliancePreset({ ...cfg, session: { ttlMs: 60_000 } } as never, 'hipaa')
    expect(out.session?.ttlMs).toBe(60_000)
  })

  it('does not mutate the config it was given', () => {
    const { cfg } = baseCfg()
    const input = { ...cfg, session: { ttlMs: 999_000_000 } }
    applyCompliancePreset(input as never, 'hipaa')
    expect(input.session.ttlMs).toBe(999_000_000)
  })

  it('FINDING: the password, mfa and api-key floors a preset resolves are not applied here', () => {
    // `applyCompliancePreset(cfg, 'fips')` reads as "this config is now fips". The
    // fourteen-character minimum, the forty-eight byte key and the backup-code
    // count are provider-level, so a deployment that applies the preset to the
    // engine and registers `passwords()` without repeating the preset gets the
    // eight-character default.
    const { cfg } = baseCfg()
    const out = applyCompliancePreset(cfg as never, 'fips')
    expect(resolveCompliance('fips').passwords.minLength).toBe(14)
    expect(out).not.toHaveProperty('passwords')
  })

  it('FINDING: the brand is non-enumerable, so spreading the returned config loses it', () => {
    // Spreading a config to add one more field is the most ordinary thing a
    // caller does, and it silently strips the marker that says which preset
    // applies.
    const { cfg } = baseCfg()
    const branded = applyCompliancePreset(cfg as never, 'hipaa')
    expect(readCompliancePreset(branded)).toBe('hipaa')
    expect(readCompliancePreset({ ...branded })).toBeNull()
  })

  it('FINDING: applying a second preset replaces the first rather than layering it', () => {
    // Each call spreads the config, which drops the non-enumerable brand, then
    // stamps its own. Calling the helper twice, the obvious way to add a preset to
    // an existing one, keeps only the last. The session windows do stay ratcheted
    // from both, so the config and the brand end up describing different policies.
    const { cfg } = baseCfg()
    const once = applyCompliancePreset(cfg as never, 'fips')
    const twice = applyCompliancePreset(once as never, 'gdpr')

    expect(readCompliancePreset(twice)).toBe('gdpr')
    expect(twice.session?.ttlMs).toBe(4 * 60 * 60 * 1000)
  })

  it('the array form brands with the whole list', () => {
    const { cfg } = baseCfg()
    const out = applyCompliancePreset(cfg as never, ['gdpr', 'hipaa'])
    expect(readCompliancePreset(out)).toEqual(['gdpr', 'hipaa'])
  })

  it('FINDING: one bad entry in a branded array disables every preset in it rather than failing', () => {
    // `readCompliancePreset` returns null for the whole array when a single entry
    // is not a known preset. A typo in a two-preset list therefore silently turns
    // compliance off instead of narrowing it.
    expect(readCompliancePreset({ __compliancePreset: ['hipaa', 'hippa'] })).toBeNull()
  })

  it('refuses a brand that is not a preset', () => {
    for (const value of [42, {}, null, true, ['gdpr', 3], []]) {
      expect(readCompliancePreset({ __compliancePreset: value })).toBeNull()
    }
  })

  it('returns null for a config that never went through the helper', () => {
    expect(readCompliancePreset({})).toBeNull()
    expect(readCompliancePreset(null)).toBeNull()
    expect(readCompliancePreset('gdpr')).toBeNull()
  })
})
