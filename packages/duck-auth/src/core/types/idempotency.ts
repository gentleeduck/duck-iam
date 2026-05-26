/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { TenantContext } from './context'

/**
 * Idempotency-key store contract. Used by mutating routes (signin,
 * signout, oauth callback, magic-link complete, etc.) to dedupe
 * client-side retries without double-charging the side-effects.
 *
 * Memory adapter ships in-tree; production swaps in a Redis-backed
 * store with `SET NX EX` for atomic put-if-absent semantics.
 */
export namespace Idempotency {
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
    get(key: string, ctx: TenantContext): Promise<ICachedResponse | null>
    /**
     * Atomically claim a key. Returns true if the caller is the first
     * to claim; false when a previous claim exists (caller should call
     * `get()` to read the cached response and replay).
     */
    claim(key: string, ttlMs: number, ctx: TenantContext): Promise<boolean>
    /** Store the response snapshot under the previously-claimed key. */
    put(key: string, response: ICachedResponse, ttlMs: number, ctx: TenantContext): Promise<void>
    /** Drop a key; used by tests + flush operations. */
    delete(key: string, ctx: TenantContext): Promise<void>
  }
}
