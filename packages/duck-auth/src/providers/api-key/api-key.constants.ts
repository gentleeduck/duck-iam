import { resolveCompliance } from '~/core/compliance'
import { AuthError } from '~/core/errors'
import type { ApiKeys } from './api-key.types'

/** Overridden per provider through `apiKeyProvider(cfg)`. */
export const DEFAULT_APIKEYS_CONFIG: ApiKeys.Cfg = {
  prefix: 'ak_live_',
  randomBytes: 32,
}

/** The least random the secret may be. 128 bits is the floor below which a bearer token is guessable,
 *  and nothing here throttles the guessing: the sign-in limiter buckets by the hash of the token
 *  presented, so an attacker trying a different key each time never meets the same bucket twice. */
export const APIKEY_MIN_RANDOM_BYTES = 16

/** The longest key `verify` accepts, which bounds the hashing a presented token costs. */
export const APIKEY_MAX_LENGTH = 512

/** Fills every {@link ApiKeys.Cfg} field from the optional input and the defaults. A `compliance`
 *  preset ratchets `randomBytes` up to that preset's floor, which a caller's own value can raise
 *  further but never drop below. */
export function toApiKeysCfg(cfg?: ApiKeys.CfgInput): ApiKeys.Cfg {
  const requested = cfg?.randomBytes ?? DEFAULT_APIKEYS_CONFIG.randomBytes
  // SECURITY: refused, not floored: `randomToken(0)` answers `''`, so every key would be the bare prefix.
  if (!Number.isInteger(requested) || requested < APIKEY_MIN_RANDOM_BYTES) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `apiKeys: randomBytes must be a whole number of bytes >= ${APIKEY_MIN_RANDOM_BYTES}, got ${String(requested)}`,
    })
  }
  const floor = cfg?.compliance ? resolveCompliance(cfg.compliance).apiKeys.randomBytes : 0
  const prefix = cfg?.prefix ?? DEFAULT_APIKEYS_CONFIG.prefix
  const randomBytes = Math.max(requested, floor)
  // A longer key would be minted and then refused by `verify`.
  const length = prefix.length + Math.ceil((randomBytes * 4) / 3)
  if (length > APIKEY_MAX_LENGTH) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `apiKeys: prefix and randomBytes make a ${length}-character key, over the ${APIKEY_MAX_LENGTH} verify accepts`,
    })
  }
  return { prefix, randomBytes }
}

/**
 * RFC 6749 section 3.3: `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`. The three gaps in that
 * range are the space, the double quote and the backslash, which is exactly what keeps a
 * space-delimited scope string unambiguous to whatever parses it back out of a token response.
 */
const SCOPE_TOKEN = /^[\u0021\u0023-\u005b\u005d-\u007e]+$/

/** Whether a string is a well-formed scope token. */
export function isScopeToken(value: string): boolean {
  return SCOPE_TOKEN.test(value)
}
