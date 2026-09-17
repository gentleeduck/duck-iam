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

/** Evidence satisfying every check `preset` names, except `missing` when one is given. */
function satisfying(preset: Compliance.Preset, missing?: Compliance.Check): Partial<Compliance.Wired> {
  const wired: Partial<Compliance.Wired> = { dataAtRest: true, mailerChannel: true }
  for (const check of resolveCompliance(preset).requiredStrictChecks) wired[check] = check !== missing
  if (missing === 'dataAtRest') wired.dataAtRest = false
  return wired
}

describe('what a preset declares against what is enforced', () => {
  it('strict() reads the preset the config was branded with', () => {
    // `readCompliancePreset` was documented as the hook `AuthEngine.strict()` uses to "auto-invoke
    // authAssertComplianceStrict so operators do not have to remember the second call", and no
    // caller existed - so branding a config and calling strict() ran none of the compliance
    // assertions and said nothing about having skipped them.
    const { cfg } = baseCfg()
    const branded = applyCompliancePreset(cfg as never, 'gdpr')
    expect(readCompliancePreset(branded)).toBe('gdpr')

    // Asserted in every environment, not only production: the preset is the operator declaring what
    // this deployment claims, unlike the production footguns `strict()` otherwise checks.
    const engine = new AuthEngine(branded as never)
    const err = (() => {
      try {
        engine.strict({ env: 'test' })
        return null
      } catch (e) {
        return e as Error & { meta: { detail: string } }
      }
    })()
    expect(err?.meta.detail).toContain('dataAtRest')
  })

  it('a deployment that supplies the evidence passes', () => {
    const { cfg } = baseCfg()
    const branded = applyCompliancePreset(cfg as never, 'gdpr')
    const engine = new AuthEngine(branded as never)
    expect(() =>
      engine.strict({
        compliance: { dataAtRest: true, exportAvailable: true, mailerChannel: true, softDeleteEnabled: true },
        env: 'test',
      }),
    ).not.toThrow()
  })

  it('minAal above 1 is refused when no mfa provider could ever satisfy it', () => {
    // Nothing compares a session's aal against `minAal` at runtime, and nothing at boot can. What
    // is checkable is that a deployment with no mfa provider registered cannot produce an AAL 2
    // session at all, so claiming hipaa with none is a contradiction rather than a silent downgrade.
    expect(resolveCompliance('hipaa').minAal).toBe(2)
    expect(resolveCompliance('fips').minAal).toBe(2)

    const { cfg } = baseCfg()
    const engine = new AuthEngine(applyCompliancePreset(cfg as never, 'hipaa') as never)
    const err = (() => {
      try {
        engine.strict({ env: 'production' })
        return null
      } catch (e) {
        return e as Error & { meta: { detail: string } }
      }
    })()
    expect(err?.meta.detail).toContain('minAal above 1 requires a registered mfa provider')
  })

  it('every check a preset declares is one the assertion demands evidence for', () => {
    // Four of the nine names the presets use were checked and the other five were strings nothing
    // read. The assertion is driven off the declared list now, so a preset naming a check that
    // nothing supplies fails rather than resolving to a requirement never looked at.
    for (const preset of ['gdpr', 'hipaa', 'soc2', 'fips'] as const) {
      // Everything the preset names is supplied, so the whole assertion passes.
      expect(() => assertComplianceStrict({ preset, wired: satisfying(preset) })).not.toThrow()
      // Then each one is withheld in turn, and every one of them has to be the difference.
      for (const check of resolveCompliance(preset).requiredStrictChecks) {
        expect(() => assertComplianceStrict({ preset, wired: satisfying(preset, check) })).toThrow(
          expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
        )
      }
    }
  })

  it('soc2 is not satisfied by an audit listener alone', () => {
    // Its other two requirements were among the unchecked names, so a deployment satisfying one of
    // three was told it satisfied soc2.
    const err = (() => {
      try {
        assertComplianceStrict({ preset: 'soc2', wired: { auditLogRetained7y: true } })
        return null
      } catch (e) {
        return e as Error & { meta: { detail: string } }
      }
    })()
    expect(err?.meta.detail).toContain('limiterRequired')
    expect(err?.meta.detail).toContain('lockoutListener')
  })

  it('gdpr demands export and soft delete, the two things it names', () => {
    const err = (() => {
      try {
        assertComplianceStrict({ preset: 'gdpr', wired: { dataAtRest: true, mailerChannel: true } })
        return null
      } catch (e) {
        return e as Error & { meta: { detail: string } }
      }
    })()
    expect(err?.meta.detail).toContain('exportAvailable')
    expect(err?.meta.detail).toContain('softDeleteEnabled')

    expect(() =>
      assertComplianceStrict({
        preset: 'gdpr',
        wired: { dataAtRest: true, exportAvailable: true, mailerChannel: true, softDeleteEnabled: true },
      }),
    ).not.toThrow()
  })

  it('an absent entry counts as unsatisfied, not as unknown', () => {
    expect(() => assertComplianceStrict({ preset: 'soc2', wired: {} })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('reports every gap in one error', () => {
    const err = (() => {
      try {
        assertComplianceStrict({ preset: 'hipaa', wired: {} })
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
    expect(() => assertComplianceStrict({ preset: 'fips', wired: satisfying('fips', 'fipsValidatedHasher') })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })
})

describe('the resolved overrides are shared, mutable objects', () => {
  it('resolving with no preset hands back a fresh object, not the module singleton', () => {
    // The no-preset branch returned `DEFAULT_OVERRIDES` by reference, so a caller adjusting what it
    // believed was its own copy edited the module singleton and every later resolution saw it.
    const first = resolveCompliance(undefined)
    first.passwords.minLength = 99
    expect(resolveCompliance(undefined).passwords.minLength).toBe(8)
  })

  it('the defaults are not aliased inside the gdpr and soc2 presets either', () => {
    // Both spread `DEFAULT_OVERRIDES`, which copies the top level and shares every nested object, so
    // one mutation rewrote two presets and the ratchet a provider applies moved with it.
    const shared = resolveCompliance(undefined)
    shared.apiKeys.randomBytes = 1
    shared.sessions.ttlMs = 1
    expect(resolveCompliance('gdpr').apiKeys.randomBytes).toBe(32)
    expect(resolveCompliance('soc2').apiKeys.randomBytes).toBe(32)
    expect(resolveCompliance('gdpr').sessions.ttlMs).toBe(7 * 24 * 60 * 60 * 1000)
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

  it('layering is order independent in every field, the check list included', () => {
    // The numeric fields all come from a min or a max, so order never mattered for them. The check
    // list was a set built by concatenation and came back in whichever order the presets were
    // listed, so anything fingerprinting a resolved policy saw two values for one deployment.
    expect(resolveCompliance(['hipaa', 'fips'])).toEqual(resolveCompliance(['fips', 'hipaa']))
  })

  it('layering a preset with itself changes nothing', () => {
    expect(resolveCompliance(['hipaa', 'hipaa'])).toEqual(resolveCompliance('hipaa'))
  })

  it('refuses a preset name the union only enforced at compile time', () => {
    expect(() => resolveCompliance('hippa' as Compliance.Preset)).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED', meta: { detail: 'unknown compliance preset: hippa' } }),
    )
  })

  // `PRESETS['constructor']` is a function off the prototype, and merging one is not a type error.
  it('refuses a prototype key as firmly as any other unknown name', () => {
    expect(() => resolveCompliance('constructor' as Compliance.Preset)).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
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

  it('applies only the engine-level floors, leaving the provider-level ones to the providers', () => {
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

  it('the brand survives the spread a caller does to add one more field', () => {
    // Non-enumerable meant the most ordinary thing a caller does silently stripped the marker
    // saying which preset applied.
    const { cfg } = baseCfg()
    const branded = applyCompliancePreset(cfg as never, 'hipaa')
    expect(readCompliancePreset(branded)).toBe('hipaa')
    expect(readCompliancePreset({ ...branded })).toBe('hipaa')
  })

  it('applying a second preset layers it onto the first', () => {
    // Each call spread the config, dropping the brand, then stamped its own - so calling the helper
    // twice, the obvious way to add a preset to an existing one, kept only the last while the
    // session windows stayed ratcheted from both, and config and brand described different policies.
    const { cfg } = baseCfg()
    const once = applyCompliancePreset(cfg as never, 'fips')
    const twice = applyCompliancePreset(once as never, 'gdpr')

    expect(readCompliancePreset(twice)).toEqual(['fips', 'gdpr'])
    expect(twice.session?.ttlMs).toBe(4 * 60 * 60 * 1000)
  })

  it('layering the same preset twice does not repeat it in the brand', () => {
    const { cfg } = baseCfg()
    const twice = applyCompliancePreset(applyCompliancePreset(cfg as never, 'fips') as never, 'fips')
    expect(readCompliancePreset(twice)).toBe('fips')
  })

  it('the array form brands with the whole list', () => {
    const { cfg } = baseCfg()
    const out = applyCompliancePreset(cfg as never, ['gdpr', 'hipaa'])
    expect(readCompliancePreset(out)).toEqual(['gdpr', 'hipaa'])
  })

  it('one bad entry in a branded array is refused, not treated as unbranded', () => {
    // Returning `null` reported the config as having no preset at all, so one misspelt entry in a
    // two-preset list turned compliance off instead of narrowing it.
    expect(() => readCompliancePreset({ __compliancePreset: ['hipaa', 'hippa'] })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('refuses a brand that is not a preset', () => {
    for (const value of [42, {}, null, true, ['gdpr', 3]]) {
      expect(() => readCompliancePreset({ __compliancePreset: value })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
    // An empty list is an absence rather than a mistake: nothing was named, so nothing applies.
    expect(readCompliancePreset({ __compliancePreset: [] })).toBeNull()
  })

  it('returns null for a config that never went through the helper', () => {
    expect(readCompliancePreset({})).toBeNull()
    expect(readCompliancePreset(null)).toBeNull()
    expect(readCompliancePreset('gdpr')).toBeNull()
  })
})
