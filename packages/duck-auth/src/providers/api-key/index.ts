/**
 * API-key provider — self-contained capability folder (mechanism A).
 * Everything api-key-related lives here: the bearer sign-in provider, the
 * facet, its config, and all types under the `ApiKeys` namespace.
 */

export { toApiKeysConfig } from './api-key.config'
export { DEFAULT_APIKEYS_CONFIG } from './api-key.constants'
export { ApiKeysFacet } from './api-key.facet'
export { apiKeyProvider, authApiKey } from './api-key.provider'
export type { ApiKeys } from './api-key.types'
