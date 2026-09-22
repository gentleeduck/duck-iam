import type { Compliance } from '~/core/compliance'
import type { ApiKeysFacet } from './api-key'

/** Api-key options, the scopes a key may carry, and the store contract over them. */
export namespace ApiKeys {
  /** The one thing {@link ApiKeysFacet} needs from the identity store: whether the key's owner is still
   *  there. Structural rather than `Identities.Store`, so the facet stays non-generic, and narrow so it
   *  cannot grow into a second way to read identities. `find` filters soft-deleted rows, so `null` means
   *  deleted or erased. */
  export type IdentityProbe = {
    find(by: { id: string }): Promise<unknown>
  }

  /** Total: every field explicit. */
  export type Cfg = {
    /** Namespaces keys by environment. Default 'ak_live_'. */
    prefix: string
    /** Length of the random portion in bytes. Default 32, which is 43 base64url chars. */
    randomBytes: number
  }

  /** Every field optional: `toApiKeysCfg` coalesces each to its default, so the facet never sees an
   *  `undefined`. */
  export type CfgInput = {
    prefix?: string
    /** Entropy per key, in bytes. */
    randomBytes?: number
    /** Ratchets `randomBytes` up to the preset's floor. */
    compliance?: Compliance.Preset | Compliance.Preset[]
  }

  export type ApiKey = {
    id: string
    identityId: string
    /** Absent on a key `create` left unscoped; `exchange` reports the same tenant back. */
    tenantId?: string
    name: string
    /** What the key may do; an exchange refuses a scope the key does not carry. */
    scopes: string[]
    createdAt: Date
    /** Moves on every write to the backing credential, a rotation or a revoke included. */
    updatedAt: Date
    /** Absent until the key is first presented. */
    lastUsedAt?: Date
    /** Absent means it does not expire of its own accord. */
    expiresAt?: Date
    /** Set once revoked; the row is kept, so a replay is refused rather than missed. */
    revokedAt?: Date
  }

  export type CreatedApiKey = {
    /** The record, with no plaintext. */
    key: ApiKey
    /** Answered once: surface it to the user, then drop it. */
    plaintext: string
  }

  /** Options for the api-key sign-in provider `authApiKey`. */
  export interface Options {
    /** The provider delegates verify and scope checks to it. */
    apiKeys: ApiKeysFacet
    /** Default `signin:api-key:`. */
    limiterKeyPrefix?: string
    /** Scopes every request must hold. Use sparingly: a per-route check calls
     *  `apiKeys.requireScopes(scopes, [...])` instead. */
    requireScopes?: string[]
  }

  /** A no-op for api-key. */
  export interface BeginInput {
    hint?: never
  }

  export interface CompleteInput {
    /** The plaintext key, `ak_live_...`. */
    token: string
  }
}
