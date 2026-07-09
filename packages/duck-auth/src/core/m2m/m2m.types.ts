export namespace M2m {
  export type Config = {
    /** Lifetime of the issued access token, ms. Default 1 hour. */
    ttlMs: number
    /**
     * When true, restrict the requested scopes to the intersection of
     * (requested, key.scopes); when false, refuse the grant when the key
     * lacks any requested scope. Default `'intersect'`.
     */
    scopeMode: 'intersect' | 'strict'
  }

  export type ExchangeInput = {
    /** Plaintext client id; for duck-auth this is the api-key id surfaced at creation. */
    clientId: string
    /** Plaintext client secret; sha-256 hashed for lookup. */
    clientSecret: string
    /** Optional space-separated oauth2 scope string. */
    scope?: string
    /** Tenant scope. */
    tenantId?: string
  }

  export type TokenResponse = {
    access_token: string
    token_type: 'Bearer'
    expires_in: number
    scope: string
  }
}
