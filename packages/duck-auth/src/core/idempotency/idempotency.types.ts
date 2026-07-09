import type { TenantContext } from '~/core/tenant/tenant.types'

export namespace Idempotency {
  /** IdempotencyFacet tuning. */
  export interface Config {
    /** TTL for cached responses, ms. Default 24 hours per RFC draft. */
    ttlMs: number
    /** When provided, requests carry the header value as the idempotency key. */
    headerName: string
    /**
     * Maximum time (ms) the loser of a `claim()` race will wait for the
     * winner's response to land before giving up and returning a 409.
     * Default 5s; tune up for executors that legitimately run longer.
     */
    pollTimeoutMs: number
  }

  /** Snapshot persisted under an idempotency key. */
  export type CachedResponse = {
    /** HTTP status the original call returned. */
    status: number
    /** Response body (serialised JSON). Channels never see PII. */
    body: unknown
    /** Optional response headers worth replaying (Set-Cookie excluded by default). */
    headers?: Record<string, string>
    /** Wall-clock createdAt for diagnostics. */
    createdAt: Date
  }

  export type Store = {
    /**
     * Get the cached response for an idempotency key. Returns null when
     * the key has never been seen OR when the TTL has elapsed.
     */
    get(key: string, ctx: TenantContext): Promise<CachedResponse | null>
    /**
     * Atomically claim a key. Returns true if the caller is the first
     * to claim; false when a previous claim exists (caller should call
     * `get()` to read the cached response and replay).
     */
    claim(key: string, ttlMs: number, ctx: TenantContext): Promise<boolean>
    /** Store the response snapshot under the previously-claimed key. */
    put(key: string, response: CachedResponse, ttlMs: number, ctx: TenantContext): Promise<void>
    /** Drop a key; used by tests + flush operations. */
    delete(key: string, ctx: TenantContext): Promise<void>
  }
}
