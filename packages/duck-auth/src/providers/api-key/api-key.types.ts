import type { Compliance } from '~/core/compliance'
import type { ApiKeysFacet } from './api-key.facet'

/**
 * Every type the api-key provider exposes lives under this one namespace, so
 * consumers reach for `ApiKeys.Config`, `ApiKeys.ApiKey`, etc. from a single
 * place.
 */
export namespace ApiKeys {
  /** Resolved, total facet config — every field explicit (null-discipline). */
  export type Config = {
    /** Token prefix; used to namespace by env. Default 'ak_live_'. */
    prefix: string
    /** Length of the random portion in bytes. Default 32 (43 base64url chars). */
    randomBytes: number
  }

  /**
   * Ergonomic, end-user-facing config. Every field optional; the boundary
   * coalesces each key to its default (`toApiKeysConfig`) so the facet never
   * sees `undefined`.
   */
  export type ConfigInput = {
    prefix?: string
    randomBytes?: number
    /** Compliance preset(s); ratchets `randomBytes` up to the preset floor. */
    compliance?: Compliance.Preset | Compliance.Preset[]
  }

  export type ApiKey = {
    id: string
    identityId: string
    name: string
    scopes: string[]
    createdAt: Date
    lastUsedAt?: Date
    expiresAt?: Date
    revokedAt?: Date
  }

  export type CreatedApiKey = {
    /** API key record (no plaintext). */
    key: ApiKey
    /** Plaintext token - returned ONCE; callers must surface to the user then drop. */
    plaintext: string
  }

  /** Options for the api-key sign-in provider {@link authApiKey}. */
  export interface Options {
    /** Bound `ApiKeysFacet`. Provider delegates verify + scope checks. */
    apiKeys: ApiKeysFacet
    /** Per-key rate-limit key prefix. Default `signin:api-key:`. */
    limiterKeyPrefix?: string
    /**
     * Scopes every request must hold. Use sparingly; per-route scope
     * checks should call `apiKeys.requireScopes(scopes, [...])`.
     */
    requireScopes?: string[]
  }

  /** Input to `begin` (no-op for api-key). */
  export interface BeginInput {
    hint?: never
  }

  /** Input to `complete`. */
  export interface CompleteInput {
    /** Plaintext key (`ak_live_...`). */
    token: string
  }
}
