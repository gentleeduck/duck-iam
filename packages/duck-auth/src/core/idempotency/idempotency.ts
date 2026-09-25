import { orNull } from '../answer'
import type { TenantContext } from '../tenant/tenant.types'
import { DEFAULT_IDEMPOTENCY_CONFIG } from './idempotency.constants'
import type { Idempotency } from './idempotency.types'

/** Driven by framework adapters: extract the header, call {@link IdempotencyImpl.handle} with an
 *  executor, and the same key presented again replays the cached response. */
export class IdempotencyImpl {
  private readonly _cfg: Idempotency.Cfg
  /** Whether the store behind this facet keeps its keys in this process, republished so `strict()` can read
   *  it without reaching into private state, as `JwtTransport.__weakSigningKey` is. */
  readonly __isInProcessIdempotency: boolean

  constructor(
    private readonly _store: Idempotency.Store | null,
    private readonly cfg?: Partial<Idempotency.Cfg>,
  ) {
    this.__isInProcessIdempotency = _store !== null && Reflect.get(_store, '__isInProcessIdempotency') === true
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

  /** So a framework adapter does not hard-code it. */
  get headerName(): string {
    return this._cfg.headerName
  }

  /** `executor` runs once, and every repeat of `key` within `ttlMs` is answered from the cached response.
   *  An executor that fails - by throwing, or by answering 5xx - caches nothing and releases the key, so
   *  the retry the client makes with that same key runs for real. */
  async handle(
    key: string,
    ctx: TenantContext,
    executor: () => Promise<Idempotency.CachedResponse>,
    opts: { identityId?: string } = {},
  ): Promise<Idempotency.CachedResponse> {
    // Skipped without a store or a key, and for a hostile-sized one: a multi-MB Idempotency-Key header
    // would bloat the store and every read of it.
    if (!this._store || typeof key !== 'string' || key.length === 0 || key.length > 256) {
      return executor()
    }
    // Scoped by identity, so one authenticated caller's cached response is never replayed to another.
    // SECURITY: with no `identityId` every anonymous caller shares the '_anon' bucket, and the key is
    // then the only thing authorising the replay - a bearer credential.
    const scopedKey = `${opts.identityId ?? '_anon'}::${key}`

    const existing = await orNull(this._store.get(scopedKey, ctx))
    if (existing) return existing

    const claimed = await this._store.claim(scopedKey, this._cfg.ttlMs, ctx)
    if (claimed) {
      let response: Idempotency.CachedResponse
      try {
        response = await executor()
      } catch (err) {
        // SECURITY: the claim is a lock on an executor that is no longer running, so it is released here
        // rather than left to `ttlMs` - a day by default - which stranded every retry of the key on a 409,
        // the one case an Idempotency-Key exists for. The 409 below covers what a release cannot: a
        // process that died mid-execution. A failed release must not cost the caller the executor's error.
        await this._store.delete(scopedKey, ctx).catch(() => {})
        throw err
      }
      // SECURITY: a 5xx is not an outcome, it is the absence of one, and pinning it to the key leaves the
      // client no way to ever complete that operation - the same defect the throw above was fixed for, since
      // whether a failing executor throws or catches its own error and answers 500 is its own style. 4xx is
      // cached deliberately: a 422 is a decision about the request, and replaying it is both cheap and right.
      if (response.status >= 500) {
        await this._store.delete(scopedKey, ctx).catch(() => {})
        return response
      }
      await this._store.put(scopedKey, response, this._cfg.ttlMs, ctx)
      return response
    }

    // Claim refused, so poll with bounded backoff for the originator's put: executing twice would
    // charge twice or mint two tokens.
    const deadline = Date.now() + this._cfg.pollTimeoutMs
    let delay = 10
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, delay))
      const settled = await orNull(this._store.get(scopedKey, ctx))
      if (settled) return settled
      delay = Math.min(delay * 2, 250)
    }
    // The originator's process died mid-execution, or the store is unreachable. A 409 beats executing
    // twice. An executor that merely failed has already released the key above, so it is not this.
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

/** Constructs the idempotency facet over a store. */
export function idempotencyImpl(...args: ConstructorParameters<typeof IdempotencyImpl>): IdempotencyImpl {
  return new IdempotencyImpl(...args)
}
