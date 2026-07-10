/**
 * API-key provider — self-contained capability folder (mechanism A).
 * Everything api-key-related lives here: the bearer sign-in provider, the
 * facet, its config, and all types under the `ApiKeys` namespace.
 */

export { ApiKeysFacet, AuthApiKeyImpl, apiKeyProvider, authApiKey } from './api-key'
export { DEFAULT_APIKEYS_CONFIG, toApiKeysCfg } from './api-key.constants'
export type { ApiKeys } from './api-key.types'
