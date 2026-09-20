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

/** Multiple presets compose by taking the stricter field. */
export function resolveCompliance(presets: Compliance.Preset | Compliance.Preset[] | undefined): Compliance.Overrides {
  // A fresh copy every time. Handing back the module singleton let a caller adjusting what it believed
  // was its own copy edit every later resolution in the process, nested objects included.
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
    // Sorted, because the set is built by concatenation and would otherwise follow the order the presets
    // were listed in, so a fingerprint of one deployment's policy had two values while every numeric field
    // was already order independent.
    requiredStrictChecks: Array.from(new Set([...a.requiredStrictChecks, ...b.requiredStrictChecks])).sort(),
    minAal: maxAal(a.minAal, b.minAal),
    requireDataAtRest: a.requireDataAtRest || b.requireDataAtRest,
    requireChannelForReset: a.requireChannelForReset || b.requireChannelForReset,
  }
}

/** Never mutates its input; the stricter rule wins per field. */
export function applyCompliancePreset<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(
  base: Engine.Cfg<Profile, Tenant, OrgMeta>,
  preset: Compliance.Preset | Compliance.Preset[],
): Engine.Cfg<Profile, Tenant, OrgMeta> {
  const overrides = resolveCompliance(preset)
  // NOTE: engine-core capabilities only. Password, mfa and api-key compliance are provider-level: pass a
  // preset to `passwords({ compliance })` and its siblings, and each ratchets its own.
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

/** The compliance preset `applyCompliancePreset` attached to a config, or null when it never ran. This is
 *  what lets `AuthEngine.strict()` invoke `authAssertComplianceStrict` itself. */
export function readCompliancePreset(cfg: unknown): Compliance.Preset | Compliance.Preset[] | null {
  if (typeof cfg !== 'object' || cfg === null) return null
  if (!('__compliancePreset' in cfg)) return null
  const value = cfg.__compliancePreset
  if (isPreset(value)) return value
  // A brand present but unreadable is a typo. Reporting it as unbranded let one misspelt entry in a
  // two-preset list turn compliance off altogether rather than narrow it.
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

/** Max of two AALs without a cast: `Math.max` answers `number` and TS cannot narrow that back to the literal
 *  union, so the three mutually exclusive cases are dispatched by hand. */
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

/** Throws `AUTH_MISCONFIGURED` with every gap listed, driven off what the preset declares rather than a
 *  fixed list, so a requirement cannot be a string nothing reads.
 *  SECURITY: `wired` is partial and an absent entry is unsatisfied; a check nobody evidenced did not pass. */
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
