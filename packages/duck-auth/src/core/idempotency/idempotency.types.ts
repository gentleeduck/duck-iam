import type { TenantContext } from '~/core/tenant/tenant.types'

/** Idempotency configuration and the store that remembers a replayed request's answer. */
export namespace Idempotency {
  export interface Cfg {
    /** TTL for cached responses, ms. Default 24 hours per RFC draft. */
    ttlMs: number
    /** When provided, requests carry the header value as the idempotency key. */
    headerName: string
    /** How long the loser of a `claim()` race waits for the winner's response before answering 409,
     *  5s by default. Raise it for an executor that legitimately runs longer. */
    pollTimeoutMs: number
  }

  /** Snapshot persisted under an idempotency key. */
  export type CachedResponse = {
    /** HTTP status the original call returned. */
    status: number
    /** The response body, serialised as JSON. */
    body: unknown
    /** Optional response headers worth replaying (Set-Cookie excluded by default). */
    headers?: Record<string, string>
    /** Wall-clock createdAt for diagnostics. */
    createdAt: Date
  }

  export type Store = {
    /** The response cached under the key. Rejects `AUTH_IDEMPOTENCY_MISS` for a key never seen, a key whose
     *  TTL has elapsed, a row that no longer parses, and a key still holding the tombstone `claim()` wrote.
     *  One code because the facet branches on all four identically: it falls through to `claim()`, and the
     *  loser of that race polls here until the winner's `put()` lands. A store that serves the tombstone as
     *  a real response breaks that protocol. A store that is down rejects its own code and stays loud. */
    get(key: string, ctx: TenantContext): Promise<CachedResponse>
    /** `true` when this caller claimed first. `false` means a previous claim exists, and the caller
     *  reads the cached response with `get()` to replay it. */
    claim(key: string, ttlMs: number, ctx: TenantContext): Promise<boolean>
    /** Stores it under the key this caller already claimed. */
    put(key: string, response: CachedResponse, ttlMs: number, ctx: TenantContext): Promise<void>
    /** For tests and flush operations. */
    delete(key: string, ctx: TenantContext): Promise<void>
  }
}
