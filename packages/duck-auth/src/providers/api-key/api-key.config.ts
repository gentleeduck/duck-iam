import { resolveCompliance } from '~/core/compliance'
import { DEFAULT_APIKEYS_CONFIG } from './api-key.constants'
import type { ApiKeys } from './api-key.types'

/**
 * Fill every {@link ApiKeys.Config} field from the optional input + defaults.
 * When a `compliance` preset is supplied, `randomBytes` is ratcheted up to that
 * preset's floor (provider-level compliance) — the user's own value can raise
 * it further but never drop below the floor.
 */
export function toApiKeysConfig(cfg?: ApiKeys.ConfigInput): ApiKeys.Config {
  const floor = cfg?.compliance ? resolveCompliance(cfg.compliance).apiKeys.randomBytes : 0
  return {
    prefix: cfg?.prefix ?? DEFAULT_APIKEYS_CONFIG.prefix,
    randomBytes: Math.max(cfg?.randomBytes ?? DEFAULT_APIKEYS_CONFIG.randomBytes, floor),
  }
}
