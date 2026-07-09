import type { TenantContext } from '../tenant/tenant.types'
import { DEFAULT_IDEMPOTENCY_CONFIG } from './idempotency.constants'
import type { Idempotency } from './idempotency.types'

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
      await new Promise((r) => setTimeout(r, delay))
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
