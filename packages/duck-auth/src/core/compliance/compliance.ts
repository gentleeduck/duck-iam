import type { Engine } from '../engine'
import { AuthError } from '../errors'
import type { Identities } from '../identities'
import type { Compliance } from './compliance.types'

const DEFAULT_OVERRIDES: Compliance.Overrides = {
  passwords: { minLength: 8 },
  sessions: { ttlMs: 7 * 24 * 60 * 60 * 1000, absoluteTtlMs: 30 * 24 * 60 * 60 * 1000, freshnessMs: 5 * 60 * 1000 },
  mfa: { backupCodeCount: 10 },
  apiKeys: { randomBytes: 32 },
  requiredStrictChecks: [],
  minAal: 1,
  requireDataAtRest: false,
  requireChannelForReset: false,
}

/** Resolve overrides for one or more presets; multiple presets compose by taking the stricter field. */
export function resolveCompliance(presets: Compliance.Preset | Compliance.Preset[] | undefined): Compliance.Overrides {
  // A fresh copy every time. The no-preset branch handed back the module singleton by reference, so
  // a caller adjusting what it believed was its own copy edited it for every later resolution in
  // the process - and the two presets that spread it shared its nested objects, so the same edit
  // rewrote them too.
  if (!presets) return copyOverrides(DEFAULT_OVERRIDES)
  const list = Array.isArray(presets) ? presets : [presets]
  let acc: Compliance.Overrides = { ...copyOverrides(DEFAULT_OVERRIDES), requiredStrictChecks: [] }
  for (const p of list) {
    if (!Object.hasOwn(PRESETS, p)) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: `unknown compliance preset: ${String(p)}` })
    }
    acc = mergeStricter(acc, PRESETS[p])
  }
  return acc
}

function copyOverrides(o: Compliance.Overrides): Compliance.Overrides {
  return {
    apiKeys: { ...o.apiKeys },
    mfa: { ...o.mfa },
    minAal: o.minAal,
    passwords: { ...o.passwords },
    requireChannelForReset: o.requireChannelForReset,
    requireDataAtRest: o.requireDataAtRest,
    requiredStrictChecks: [...o.requiredStrictChecks],
    sessions: { ...o.sessions },
  }
}

const PRESETS: Record<Compliance.Preset, Compliance.Overrides> = {
  gdpr: {
    ...copyOverrides(DEFAULT_OVERRIDES),
    requiredStrictChecks: ['exportAvailable', 'softDeleteEnabled'],
    requireDataAtRest: true,
    requireChannelForReset: true,
  },
  hipaa: {
    passwords: { minLength: 12 },
    sessions: {
      ttlMs: 60 * 60 * 1000, // 1h sliding
      absoluteTtlMs: 8 * 60 * 60 * 1000, // 8h hard cap
      freshnessMs: 5 * 60 * 1000,
    },
    mfa: { backupCodeCount: 10 },
    apiKeys: { randomBytes: 32 },
    requiredStrictChecks: ['baaCompliantChannel', 'auditLogRetained7y', 'dataAtRest'],
    minAal: 2,
    requireDataAtRest: true,
    requireChannelForReset: true,
  },
  soc2: {
    ...copyOverrides(DEFAULT_OVERRIDES),
    requiredStrictChecks: ['lockoutListener', 'limiterRequired', 'auditLogRetained7y'],
  },
  fips: {
    passwords: { minLength: 14 },
    sessions: {
      ttlMs: 4 * 60 * 60 * 1000,
      absoluteTtlMs: 12 * 60 * 60 * 1000,
      freshnessMs: 5 * 60 * 1000,
    },
    mfa: { backupCodeCount: 10 },
    apiKeys: { randomBytes: 48 },
    requiredStrictChecks: ['fipsValidatedHasher', 'webauthnAttestationDirect'],
    minAal: 2,
    requireDataAtRest: true,
    requireChannelForReset: true,
  },
}

function mergeStricter(a: Compliance.Overrides, b: Compliance.Overrides): Compliance.Overrides {
  return {
    passwords: { minLength: Math.max(a.passwords.minLength, b.passwords.minLength) },
    sessions: {
      ttlMs: Math.min(a.sessions.ttlMs, b.sessions.ttlMs),
      absoluteTtlMs: Math.min(a.sessions.absoluteTtlMs, b.sessions.absoluteTtlMs),
      freshnessMs: Math.min(a.sessions.freshnessMs, b.sessions.freshnessMs),
    },
    mfa: { backupCodeCount: Math.max(a.mfa.backupCodeCount, b.mfa.backupCodeCount) },
    apiKeys: { randomBytes: Math.max(a.apiKeys.randomBytes, b.apiKeys.randomBytes) },
    // Sorted, because the set is built by concatenation and otherwise comes back in whichever order
    // the presets were listed - so anything fingerprinting a resolved policy saw two values for one
    // deployment while every numeric field was already order independent.
    requiredStrictChecks: Array.from(new Set([...a.requiredStrictChecks, ...b.requiredStrictChecks])).sort(),
    minAal: maxAal(a.minAal, b.minAal),
    requireDataAtRest: a.requireDataAtRest || b.requireDataAtRest,
    requireChannelForReset: a.requireChannelForReset || b.requireChannelForReset,
  }
}

/** Apply preset overrides to an AuthEngine config; never mutates input, stricter rule wins per field. */
export function applyCompliancePreset<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(
  base: Engine.Cfg<Profile, Tenant, OrgMeta>,
  preset: Compliance.Preset | Compliance.Preset[],
): Engine.Cfg<Profile, Tenant, OrgMeta> {
  const overrides = resolveCompliance(preset)
  // Attach the resolved overrides via `__compliancePreset` so
  // `AuthEngine.strict` can apply `authAssertComplianceStrict` automatically.
  // NOTE: password, mfa + api-key compliance are provider-level now — pass a
  // preset to `passwords({ compliance })` / `mfaProvider({ compliance })`
  // / `apiKeyProvider({ compliance })` and each ratchets its own field. Only
  // engine-core capabilities (session) are ratcheted here.
  // Layered, not replaced. Each call spread the config, which dropped the non-enumerable brand,
  // then stamped its own - so calling the helper twice, the obvious way to add a preset to an
  // existing one, kept only the last while the session windows stayed ratcheted from both, and the
  // config and its brand ended up describing different policies.
  const existing = readCompliancePreset(base)
  const layered = dedupePresets([...(existing === null ? [] : [existing].flat()), ...[preset].flat()])
  const out = {
    ...base,
    session: {
      ...(base.session ?? {}),
      ttlMs: Math.min(base.session?.ttlMs ?? Infinity, overrides.sessions.ttlMs),
      absoluteTtlMs: Math.min(base.session?.absoluteTtlMs ?? Infinity, overrides.sessions.absoluteTtlMs),
      freshnessMs: Math.min(base.session?.freshnessMs ?? Infinity, overrides.sessions.freshnessMs),
    },
  }
  // Enumerable, so an ordinary `{ ...cfg, extra }` carries it. Non-enumerable meant the most
  // ordinary thing a caller does silently stripped the marker saying which preset applied.
  Object.defineProperty(out, '__compliancePreset', {
    value: layered.length === 1 ? layered[0] : layered,
    enumerable: true,
    configurable: false,
    writable: false,
  })
  return out
}

function dedupePresets(list: Compliance.Preset[]): Compliance.Preset[] {
  return [...new Set(list)]
}

/**
 * Resolve any compliance preset attached to a config via
 * `authApplyCompliancePreset`. Returns null when the config was not
 * processed by that helper. Used by `AuthEngine.strict()` to
 * auto-invoke `authAssertComplianceStrict` so operators do not have to
 * remember the second call.
 */
export function readCompliancePreset(cfg: unknown): Compliance.Preset | Compliance.Preset[] | null {
  if (typeof cfg !== 'object' || cfg === null) return null
  if (!('__compliancePreset' in cfg)) return null
  const value = cfg.__compliancePreset
  if (isPreset(value)) return value
  // A brand that is present but not readable is a typo, and returning `null` for it reported the
  // config as unbranded - so one misspelt entry in a two-preset list turned compliance off
  // altogether instead of narrowing it.
  if (Array.isArray(value)) {
    const bad = value.filter((v) => !isPreset(v))
    if (bad.length > 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `unknown compliance preset in brand: ${bad.map((b) => String(b)).join(', ')}`,
      })
    }
    return value.length > 0 ? (value as Compliance.Preset[]) : null
  }
  throw new AuthError('AUTH_MISCONFIGURED', {
    detail: `compliance brand is not a preset or a list of presets: ${String(value)}`,
  })
}

const PRESET_VALUES: ReadonlySet<string> = new Set<Compliance.Preset>(['gdpr', 'hipaa', 'soc2', 'fips'])

function isPreset(v: unknown): v is Compliance.Preset {
  return typeof v === 'string' && PRESET_VALUES.has(v)
}

/**
 * Max of two AAL values without an `as 1 | 2 | 3` cast. `Math.max`
 * returns `number`; TS cannot narrow it back to the literal union, so
 * we dispatch explicitly. The cases are mutually exclusive in [1, 3].
 */
function maxAal(a: 1 | 2 | 3, b: 1 | 2 | 3): 1 | 2 | 3 {
  if (a === 3 || b === 3) return 3
  if (a === 2 || b === 2) return 2
  return 1
}

/** What each check demands, said in the words an operator can act on. */
const CHECK_DEMANDS: Record<Compliance.Check, string> = {
  auditLogRetained7y: 'audit-log listener required (7y retention)',
  baaCompliantChannel: 'every channel must be covered by a signed BAA',
  dataAtRest: 'dataAtRest adapter required',
  exportAvailable: 'a subject-access export path must be reachable',
  fipsValidatedHasher: 'FIPS-validated hasher required (Argon2id with FIPS params)',
  limiterRequired: 'a real limiter must be wired (AuthNoopLimiter does not count)',
  lockoutListener: 'a `lockout` event handler must be subscribed',
  softDeleteEnabled: 'identity deletion must be soft, so erasure can be honoured and audited',
  webauthnAttestationDirect: 'webauthn registration must request direct attestation',
}

/**
 * Validate runtime wiring against a compliance preset; throws `AUTH/MISCONFIGURED` listing every gap.
 *
 * Driven off what the preset declares rather than a fixed list of four. Four of the nine names the
 * presets use were checked and the other five were strings nothing read, so `soc2` passed on one of
 * its three requirements and `gdpr` passed without either of the two things it names.
 *
 * `wired` is partial and an absent entry counts as unsatisfied: a check nobody supplied evidence
 * for is not a check that passed.
 */
export function assertComplianceStrict(opts: {
  preset: Compliance.Preset | Compliance.Preset[]
  wired: Partial<Compliance.Wired>
}): void {
  const overrides = resolveCompliance(opts.preset)
  const errors: string[] = []
  if (overrides.requireDataAtRest && opts.wired.dataAtRest !== true) {
    errors.push(`compliance: ${CHECK_DEMANDS.dataAtRest}`)
  }
  if (overrides.requireChannelForReset && opts.wired.mailerChannel !== true) {
    errors.push('compliance: mailer/channel adapter required for password-reset + magic-link flows')
  }
  for (const check of overrides.requiredStrictChecks) {
    if (check === 'dataAtRest' && overrides.requireDataAtRest) continue
    if (opts.wired[check] !== true) errors.push(`compliance: ${check} - ${CHECK_DEMANDS[check]}`)
  }
  if (errors.length > 0) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `compliance strict checks failed:\n  - ${errors.join('\n  - ')}`,
    })
  }
}
