/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { TenantContext } from '../types/context'
import type { Idempotency } from '../types/idempotency'

/**
 * In-memory Idempotency store. Dev / test only; production swaps in a
 * Redis-backed implementation via `SET NX EX` for true atomic claim
 * across multiple processes.
 *
 * Keys are scoped by tenantId so two tenants supplying the same
 * Idempotency-Key cannot collide.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class MemoryIdempotencyStore implements Idempotency.IStore {
  private readonly _entries = new Map<
    string,
    { response: Idempotency.ICachedResponse; expiresAt: number; claimedAt: number }
  >()

  /** Compose a tenant-scoped storage key. */
  private _k(key: string, ctx: TenantContext): string {
    return `${ctx.tenantId ?? '_default'}::${key}`
  }

  async get(key: string, ctx: TenantContext): Promise<Idempotency.ICachedResponse | null> {
    const entry = this._entries.get(this._k(key, ctx))
    if (!entry) return null
    if (entry.expiresAt < Date.now()) {
      this._entries.delete(this._k(key, ctx))
      return null
    }
    return entry.response
  }

  async claim(key: string, ttlMs: number, ctx: TenantContext): Promise<boolean> {
    const storeKey = this._k(key, ctx)
    const existing = this._entries.get(storeKey)
    const now = Date.now()
    if (existing && existing.expiresAt >= now) return false
    this._entries.set(storeKey, {
      response: { status: 0, body: null, createdAt: now },
      expiresAt: now + ttlMs,
      claimedAt: now,
    })
    return true
  }

  async put(key: string, response: Idempotency.ICachedResponse, ttlMs: number, ctx: TenantContext): Promise<void> {
    this._entries.set(this._k(key, ctx), {
      response: { ...response, createdAt: response.createdAt ?? Date.now() },
      expiresAt: Date.now() + ttlMs,
      claimedAt: Date.now(),
    })
  }

  async delete(key: string, ctx: TenantContext): Promise<void> {
    this._entries.delete(this._k(key, ctx))
  }
}

export interface IdempotencyFacetConfig {
  /** TTL for cached responses, ms. Default 24 hours per RFC draft. */
  ttlMs: number
  /** When provided, requests carry the header value as the idempotency key. */
  headerName: string
}

export const DEFAULT_IDEMPOTENCY_CONFIG: IdempotencyFacetConfig = {
  ttlMs: 24 * 60 * 60 * 1000,
  headerName: 'idempotency-key',
}

/**
 * Idempotency facet. Driven by framework adapters: extract the header,
 * call {@link IdempotencyFacet.handle} with an executor; the facet
 * replays the cached response when the same key is presented again.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class IdempotencyFacet {
  constructor(
    private readonly _store: Idempotency.IStore | null,
    private readonly _cfg: IdempotencyFacetConfig = DEFAULT_IDEMPOTENCY_CONFIG,
  ) {}

  /** True when an Idempotency store is wired; framework adapters skip the dance otherwise. */
  enabled(): boolean {
    return this._store !== null
  }

  /** Read the configured header name (so framework adapters don't hard-code it). */
  get headerName(): string {
    return this._cfg.headerName
  }

  /**
   * Wrap a mutating route handler with idempotency semantics.
   *
   * @param key plaintext Idempotency-Key header value (caller validates length)
   * @param ctx tenant scope
   * @param executor the original work the route would do; returns the
   *                 status + body to persist
   * @returns the executor's result on first invocation; the cached
   *          response on subsequent invocations within ttlMs
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async handle(
    key: string,
    ctx: TenantContext,
    executor: () => Promise<Idempotency.ICachedResponse>,
  ): Promise<Idempotency.ICachedResponse> {
    if (!this._store || key.length === 0) {
      return executor()
    }
    const existing = await this._store.get(key, ctx)
    if (existing) return existing

    const claimed = await this._store.claim(key, this._cfg.ttlMs, ctx)
    if (!claimed) {
      // Race: another caller claimed first. Re-read.
      const settled = await this._store.get(key, ctx)
      if (settled) return settled
      // Race + race: fall through to execute. This is best-effort
      // without distributed locking; production Redis store eliminates
      // it via SET NX EX semantics.
    }
    const response = await executor()
    await this._store.put(key, response, this._cfg.ttlMs, ctx)
    return response
  }
}

/**
 * Namespace merge for IdempotencyFacet. Co-locates the config + input + output
 * shapes alongside the class via TS class+namespace merging. Consumers can
 * write either the flat name (e.g. IdempotencyFacetConfig) or the
 * namespaced form (IdempotencyFacet.IConfig); both
 * resolve to the same type.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace IdempotencyFacet {
  /** Alias for the flat `IdempotencyFacetConfig` type. */
  export type IConfig = IdempotencyFacetConfig
}
