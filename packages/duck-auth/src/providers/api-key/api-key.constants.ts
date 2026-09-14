import { resolveCompliance } from '~/core/compliance'
import type { ApiKeys } from './api-key.types'

/** Default api-key facet config; overridden per-provider via `apiKeyProvider(cfg)`. */
export const DEFAULT_APIKEYS_CONFIG: ApiKeys.Cfg = {
  prefix: 'ak_live_',
  randomBytes: 32,
}

/**
 * Fill every {@link ApiKeys.Cfg} field from the optional input + defaults.
 * When a `compliance` preset is supplied, `randomBytes` is ratcheted up to that
 * preset's floor (provider-level compliance) — the user's own value can raise
 * it further but never drop below the floor.
 */
export function toApiKeysCfg(cfg?: ApiKeys.CfgInput): ApiKeys.Cfg {
  const floor = cfg?.compliance ? resolveCompliance(cfg.compliance).apiKeys.randomBytes : 0
  return {
    prefix: cfg?.prefix ?? DEFAULT_APIKEYS_CONFIG.prefix,
    randomBytes: Math.max(cfg?.randomBytes ?? DEFAULT_APIKEYS_CONFIG.randomBytes, floor),
  }
}

/**
 * RFC 6749 section 3.3: `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`. The three gaps in that
 * range are the space, the double quote and the backslash, which is exactly what keeps a
 * space-delimited scope string unambiguous to whatever parses it back out of a token response.
 */
const SCOPE_TOKEN = /^[\u0021\u0023-\u005b\u005d-\u007e]+$/

export function isScopeToken(value: string): boolean {
  return SCOPE_TOKEN.test(value)
}
