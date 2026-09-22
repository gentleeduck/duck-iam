import type { M2m } from './m2m.types'

export const DEFAULT_M2M_CONFIG: M2m.Cfg = {
  ttlMs: 60 * 60 * 1000,
  scopeMode: 'intersect',
}

/** A ttl outside this range is a configuration mistake, not a policy: below it the token is expired on arrival. */
export const M2M_TTL_MIN_MS = 1_000
export const M2M_TTL_MAX_MS = 30 * 24 * 60 * 60 * 1000

/** Caps on the scope request. */
export const M2M_SCOPE_MAX_LENGTH = 4096
export const M2M_SCOPE_MAX_TOKENS = 64

/** Cap on the credential pair, which is a limiter key and a sha256 input before it is anything else.
 *  512 as in `ApiKeyProvider.complete`, which guards its token for the same two reasons. */
export const M2M_CLIENT_FIELD_MAX_LENGTH = 512
