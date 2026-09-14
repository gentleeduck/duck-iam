import type { M2m } from './m2m.types'

export const DEFAULT_M2M_CONFIG: M2m.Cfg = {
  ttlMs: 60 * 60 * 1000,
  scopeMode: 'intersect',
}

/** A ttl outside this range is a configuration mistake, not a policy: below it the token is expired on arrival. */
export const M2M_TTL_MIN_MS = 1_000
export const M2M_TTL_MAX_MS = 30 * 24 * 60 * 60 * 1000

/** Caps on the one input the client controls that is not the secret. */
export const M2M_SCOPE_MAX_LENGTH = 4096
export const M2M_SCOPE_MAX_TOKENS = 64
