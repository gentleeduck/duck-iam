/** Machine-to-machine grants: the client-credentials exchange and the scopes it may mint. */
export namespace M2m {
  export type Cfg = {
    /** Lifetime of the issued access token, ms. Default 1 hour. */
    ttlMs: number
    /** `'intersect'` (default) narrows the request to what the key holds; `'strict'` refuses a grant naming
     *  any scope the key lacks. */
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
