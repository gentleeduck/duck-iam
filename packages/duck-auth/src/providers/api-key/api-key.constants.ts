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
