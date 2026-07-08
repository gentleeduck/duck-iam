import type { ApiKeys } from './api-key.types'

/** Default api-key facet config; overridden per-provider via `apiKeyProvider(cfg)`. */
export const DEFAULT_APIKEYS_CONFIG: ApiKeys.Config = {
  prefix: 'ak_live_',
  randomBytes: 32,
}
