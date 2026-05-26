/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { AuthRootConfig } from './auth'
import { AuthErrorObject } from './errors'

/**
 * Compliance preset id. Apps pass one (or an array) to ratchet defaults
 * + enforce stricter strict() checks.
 *
 *   gdpr  - soft-delete required, dataAtRest required, export endpoint
 *           mandatory, audit log retained
 *   hipaa - everything in gdpr + AAL >= 2 on all sessions, password
 *           length bumped to 12, BAA-compliant channels only
 *   soc2  - strict() failure on missing limiter / events listeners +
 *           7y audit retention
 *   fips  - WebAuthn attestation 'direct' required + only FIPS-validated
 *           algorithms (EdDSA + scrypt with bigger params + no SHA-1)
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export type CompliancePreset = 'gdpr' | 'hipaa' | 'soc2' | 'fips'

/**
 * Compliance overrides applied on top of the consumer's config. Defaults
 * here are conservative; consumers can layer presets (gdpr + soc2) but
 * library refuses conflicting combinations via strict().
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface ComplianceOverrides {
  passwords: { minLength: number }
  sessions: { ttlMs: number; absoluteTtlMs: number; freshnessMs: number }
  mfa: { backupCodeCount: number }
  apiKeys: { randomBytes: number }
  /** Names of strict() checks the preset insists on. */
  requiredStrictChecks: string[]
  /** Minimum AAL enforced on every session created during signin. */
  minAal: 1 | 2 | 3
  /** When true, dataAtRest adapter required at boot. */
  requireDataAtRest: boolean
  /** When true, mailer / channel adapter required for any provider that needs it. */
  requireChannelForReset: boolean
}

const DEFAULT_OVERRIDES: ComplianceOverrides = {
  passwords: { minLength: 8 },
  sessions: { ttlMs: 7 * 24 * 60 * 60 * 1000, absoluteTtlMs: 30 * 24 * 60 * 60 * 1000, freshnessMs: 5 * 60 * 1000 },
  mfa: { backupCodeCount: 10 },
  apiKeys: { randomBytes: 32 },
  requiredStrictChecks: [],
  minAal: 1,
  requireDataAtRest: false,
  requireChannelForReset: false,
}

/**
 * Resolve overrides for a preset. Multiple presets compose by taking the
 * stricter value at each field.
 *
 * @example
 * ```ts
 * const cfg = resolveCompliance(['gdpr', 'soc2'])
 * // cfg.minAal === 1 (gdpr)
 * // cfg.requireDataAtRest === true (gdpr)
 * // cfg.requiredStrictChecks includes both gdpr + soc2 lists
 * ```
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function resolveCompliance(presets: CompliancePreset | CompliancePreset[] | undefined): ComplianceOverrides {
  if (!presets) return DEFAULT_OVERRIDES
  const list = Array.isArray(presets) ? presets : [presets]
  let acc: ComplianceOverrides = { ...DEFAULT_OVERRIDES, requiredStrictChecks: [] }
  for (const p of list) {
    const overlay = PRESETS[p]
    acc = mergeStricter(acc, overlay)
  }
  return acc
}

const PRESETS: Record<CompliancePreset, ComplianceOverrides> = {
  gdpr: {
    ...DEFAULT_OVERRIDES,
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
    ...DEFAULT_OVERRIDES,
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

function mergeStricter(a: ComplianceOverrides, b: ComplianceOverrides): ComplianceOverrides {
  return {
    passwords: { minLength: Math.max(a.passwords.minLength, b.passwords.minLength) },
    sessions: {
      ttlMs: Math.min(a.sessions.ttlMs, b.sessions.ttlMs),
      absoluteTtlMs: Math.min(a.sessions.absoluteTtlMs, b.sessions.absoluteTtlMs),
      freshnessMs: Math.min(a.sessions.freshnessMs, b.sessions.freshnessMs),
    },
    mfa: { backupCodeCount: Math.max(a.mfa.backupCodeCount, b.mfa.backupCodeCount) },
    apiKeys: { randomBytes: Math.max(a.apiKeys.randomBytes, b.apiKeys.randomBytes) },
    requiredStrictChecks: Array.from(new Set([...a.requiredStrictChecks, ...b.requiredStrictChecks])),
    minAal: Math.max(a.minAal, b.minAal) as 1 | 2 | 3,
    requireDataAtRest: a.requireDataAtRest || b.requireDataAtRest,
    requireChannelForReset: a.requireChannelForReset || b.requireChannelForReset,
  }
}

/**
 * Apply preset overrides to a user-supplied AuthRoot config.
 * Returns a fresh config object; never mutates the input.
 *
 * The stricter rule wins for every field: a preset that bumps password
 * minLength to 12 takes precedence over a user setting of 8; a preset
 * that caps session TTL to 1h takes precedence over a user setting of 7d.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function applyCompliancePreset<Profile = unknown, Tenant = string, OrgMeta = unknown>(
  base: AuthRootConfig<Profile, Tenant, OrgMeta>,
  preset: CompliancePreset | CompliancePreset[],
): AuthRootConfig<Profile, Tenant, OrgMeta> {
  const overrides = resolveCompliance(preset)
  return {
    ...base,
    passwords: {
      ...(base.passwords ?? {}),
      minLength: Math.max(base.passwords?.minLength ?? 0, overrides.passwords.minLength),
    },
    session: {
      ...(base.session ?? {}),
      ttlMs: Math.min(base.session?.ttlMs ?? Infinity, overrides.sessions.ttlMs),
      absoluteTtlMs: Math.min(base.session?.absoluteTtlMs ?? Infinity, overrides.sessions.absoluteTtlMs),
      freshnessMs: Math.min(base.session?.freshnessMs ?? Infinity, overrides.sessions.freshnessMs),
    },
    mfa: {
      ...(base.mfa ?? {}),
      backupCodeCount: Math.max(base.mfa?.backupCodeCount ?? 0, overrides.mfa.backupCodeCount),
    },
    apiKeys: {
      ...(base.apiKeys ?? {}),
      randomBytes: Math.max(base.apiKeys?.randomBytes ?? 0, overrides.apiKeys.randomBytes),
    },
  }
}

/**
 * Validate that an AuthRoot's runtime state satisfies the compliance
 * preset's strict checks. Called from {@link AuthRoot.strict} when
 * compliance is configured. Throws AUTH/MISCONFIGURED with the failure
 * list when any check fails.
 *
 * Caller supplies `wired` flags describing what is hooked up; library
 * cannot introspect every adapter at the type level.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function assertComplianceStrict(opts: {
  preset: CompliancePreset | CompliancePreset[]
  wired: {
    dataAtRest: boolean
    mailerChannel: boolean
    auditListener: boolean
    fipsValidatedHasher: boolean
  }
}): void {
  const overrides = resolveCompliance(opts.preset)
  const errors: string[] = []
  if (overrides.requireDataAtRest && !opts.wired.dataAtRest) {
    errors.push('compliance: dataAtRest adapter required')
  }
  if (overrides.requireChannelForReset && !opts.wired.mailerChannel) {
    errors.push('compliance: mailer/channel adapter required for password-reset + magic-link flows')
  }
  if (overrides.requiredStrictChecks.includes('auditLogRetained7y') && !opts.wired.auditListener) {
    errors.push('compliance: audit-log listener required (7y retention)')
  }
  if (overrides.requiredStrictChecks.includes('fipsValidatedHasher') && !opts.wired.fipsValidatedHasher) {
    errors.push('compliance: FIPS-validated hasher required (Argon2id with FIPS params)')
  }
  if (errors.length > 0) {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: `compliance strict checks failed:\n  - ${errors.join('\n  - ')}`,
    })
  }
}
