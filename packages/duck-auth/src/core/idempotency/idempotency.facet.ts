import { isExpiredAt } from '../credentials/credentials'
import type { TenantContext } from '../types/infra'
import { DEFAULT_IDEMPOTENCY_CONFIG } from './idempotency.constants'
import type { Idempotency } from './idempotency.types'

/**
 * In-memory Idempotency store. Dev / test only; production swaps in a
 * Redis-backed implementation via `SET NX EX` for true atomic claim
 * across multiple processes.
 *
 * Keys are scoped by tenantId so two tenants supplying the same
 * Idempotency-Key cannot collide.
 */
export class MemoryIdempotencyStore implements Idempotency.Store {
  private readonly _entries = new Map<
    string,
    { response: Idempotency.CachedResponse; expiresAt: number; claimedAt: number }
  >()

  /** Compose a tenant-scoped storage key. */
  private _k(key: string, ctx: TenantContext): string {
    return `${ctx.tenantId ?? '_default'}::${key}`
  }

  async get(key: string, ctx: TenantContext): Promise<Idempotency.CachedResponse | null> {
    const entry = this._entries.get(this._k(key, ctx))
    if (!entry) return null
    // Non-finite expiresAt would slip `NaN < now == false` past TTL.
    if (isExpiredAt(entry.expiresAt)) {
      this._entries.delete(this._k(key, ctx))
      return null
    }
    // Tombstone (status 0, body null) reports as "not yet" so caller polls.
    if (entry.response.status === 0 && entry.response.body === null) return null
    return entry.response
  }

  async claim(key: string, ttlMs: number, ctx: TenantContext): Promise<boolean> {
    const storeKey = this._k(key, ctx)
    const existing = this._entries.get(storeKey)
    const now = Date.now()
    if (existing && existing.expiresAt >= now) return false
    // Non-finite ttlMs would set expiresAt=NaN and freeze the slot forever
    // (NaN >= N evaluates false). Clamp to a sane window.
    const safeTtl = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    this._entries.set(storeKey, {
      response: { status: 0, body: null, createdAt: new Date(now) },
      expiresAt: now + safeTtl,
      claimedAt: now,
    })
    return true
  }

  async put(key: string, response: Idempotency.CachedResponse, ttlMs: number, ctx: TenantContext): Promise<void> {
    // Same NaN-bypass defense as claim(): clamp ttl to a sane window.
    const safeTtl = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    const now = Date.now()
    this._entries.set(this._k(key, ctx), {
      response: { ...response, createdAt: response.createdAt ?? new Date(now) },
      expiresAt: now + safeTtl,
      claimedAt: now,
    })
  }

  async delete(key: string, ctx: TenantContext): Promise<void> {
    this._entries.delete(this._k(key, ctx))
  }
}

/**
 * Idempotency facet. Driven by framework adapters: extract the header,
 * call {@link IdempotencyFacet.handle} with an executor; the facet
 * replays the cached response when the same key is presented again.
 */
export class IdempotencyFacet {
  constructor(
    private readonly _store: Idempotency.Store | null,
    private readonly _cfg: Idempotency.Config = DEFAULT_IDEMPOTENCY_CONFIG,
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
   */
  async handle(
    key: string,
    ctx: TenantContext,
    executor: () => Promise<Idempotency.CachedResponse>,
    opts: { identityId?: string } = {},
  ): Promise<Idempotency.CachedResponse> {
    // Skip when no store configured, key is missing, or key is hostile-sized
    // (multi-MB Idempotency-Key headers would bloat the store + every read).
    if (!this._store || typeof key !== 'string' || key.length === 0 || key.length > 256) {
      return executor()
    }
    // Scope the key by identity so a cached response for Alice is
    // never replayed to Bob. Anonymous routes fall back to '_anon'.
    const scopedKey = `${opts.identityId ?? '_anon'}::${key}`

    const existing = await this._store.get(scopedKey, ctx)
    if (existing) return existing

    const claimed = await this._store.claim(scopedKey, this._cfg.ttlMs, ctx)
    if (claimed) {
      const response = await executor()
      await this._store.put(scopedKey, response, this._cfg.ttlMs, ctx)
      return response
    }

    // Claim refused; poll with bounded backoff for the originator's PUT.
    // Double-executing would charge twice / mint two tokens.
    const deadline = Date.now() + this._cfg.pollTimeoutMs
    let delay = 10
    while (Date.now() < deadline) {
      await sleep(delay)
      const settled = await this._store.get(scopedKey, ctx)
      if (settled) return settled
      delay = Math.min(delay * 2, 250)
    }
    // The originator either crashed mid-execution or the store is
    // unreachable. Surface a 409 instead of double-executing; the
    // client can retry with a fresh key.
    return { status: 409, body: { error: 'idempotency-conflict' }, createdAt: new Date() }
  }
}

/** Promise-flavoured setTimeout. Kept private so the facet has zero
 * runtime dependencies beyond the store contract. */
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}
