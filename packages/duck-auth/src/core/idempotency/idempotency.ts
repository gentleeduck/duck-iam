import type { TenantContext } from '../tenant/tenant.types'
import { DEFAULT_IDEMPOTENCY_CONFIG } from './idempotency.constants'
import type { Idempotency } from './idempotency.types'

/**
 * Idempotency facet. Driven by framework adapters: extract the header,
 * call {@link IdempotencyImpl.handle} with an executor; the facet
 * replays the cached response when the same key is presented again.
 */
export class IdempotencyImpl {
  private readonly _cfg: Idempotency.Cfg

  constructor(
    private readonly _store: Idempotency.Store | null,
    private readonly cfg?: Partial<Idempotency.Cfg>,
  ) {
    this._cfg = {
      ttlMs: this.cfg?.ttlMs ?? DEFAULT_IDEMPOTENCY_CONFIG.ttlMs,
      headerName: this.cfg?.headerName ?? DEFAULT_IDEMPOTENCY_CONFIG.headerName,
      pollTimeoutMs: this.cfg?.pollTimeoutMs ?? DEFAULT_IDEMPOTENCY_CONFIG.pollTimeoutMs,
    }
  }

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

/**
 * Anything the `idempotency` config key accepts: the facet itself, or a bare
 * store to wrap in one. Mirrors how `limiter` takes a ready-made `Limiter.Me`,
 * so `idempotency: redisIdempotency({ redis })` reads like
 * `limiter: redisLimiter({ redis, max, windowMs })`.
 */
export type IdempotencyInput = IdempotencyImpl | Idempotency.Store

/** True for the facet rather than a store; the two share no method names. */
function isFacet(value: IdempotencyInput): value is IdempotencyImpl {
  return value instanceof IdempotencyImpl
}

/**
 * Normalise whatever the config supplied into a facet. Used by the engine so a
 * caller can pass either spelling, and by {@link idempotency} so wrapping twice
 * is a no-op rather than an error.
 */
export function resolveIdempotency(value: IdempotencyInput, cfg?: Partial<Idempotency.Cfg>): IdempotencyImpl {
  return isFacet(value) ? value : new IdempotencyImpl(value, cfg)
}

/**
 * Wrap a store in the facet. Accepts a facet too, so composing with the
 * store-specific factories below stays valid.
 */
export function idempotency(store: IdempotencyInput, cfg?: Partial<Idempotency.Cfg>): IdempotencyImpl {
  return resolveIdempotency(store, cfg)
}

/** Factory around {@link IdempotencyImpl}, for callers who prefer functions to `new`. */
export function idempotencyImpl(...args: ConstructorParameters<typeof IdempotencyImpl>): IdempotencyImpl {
  return new IdempotencyImpl(...args)
}
