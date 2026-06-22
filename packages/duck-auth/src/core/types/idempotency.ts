import type { AuthTenantContext } from './context'

/** AuthIdempotency-key store contract; Redis adapter uses `SET NX EX` for atomic put-if-absent. */
export namespace AuthIdempotency {
  /** Snapshot persisted under an idempotency key. */
  export interface ICachedResponse {
    /** HTTP status the original call returned. */
    status: number
    /** Response body (serialised JSON). Channels never see PII. */
    body: unknown
    /** Optional response headers worth replaying (Set-Cookie excluded by default). */
    headers?: Record<string, string>
    /** Wall-clock createdAt for diagnostics. */
    createdAt: number
  }

  export interface IStore {
    /**
     * Get the cached response for an idempotency key. Returns null when
     * the key has never been seen OR when the TTL has elapsed.
     */
    get(key: string, ctx: AuthTenantContext): Promise<ICachedResponse | null>
    /**
     * Atomically claim a key. Returns true if the caller is the first
     * to claim; false when a previous claim exists (caller should call
     * `get()` to read the cached response and replay).
     */
    claim(key: string, ttlMs: number, ctx: AuthTenantContext): Promise<boolean>
    /** Store the response snapshot under the previously-claimed key. */
    put(key: string, response: ICachedResponse, ttlMs: number, ctx: AuthTenantContext): Promise<void>
    /** Drop a key; used by tests + flush operations. */
    delete(key: string, ctx: AuthTenantContext): Promise<void>
  }
}
