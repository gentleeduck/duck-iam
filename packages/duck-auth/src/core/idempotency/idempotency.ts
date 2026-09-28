import { orNull } from '../answer'
import { AuthError } from '../errors'
import type { TenantContext } from '../tenant/tenant.types'
import { DEFAULT_IDEMPOTENCY_CONFIG } from './idempotency.constants'
import type { Idempotency } from './idempotency.types'

/** The host builds one (`redisIdempotency`, `valkeyIdempotency`, or `idempotency` over its own store) and
 *  calls {@link IdempotencyImpl.handle} with the request's key and an executor; the same key presented again
 *  replays the cached response. The engine holds none, since none of its routes replays a response. */
export class IdempotencyImpl {
  private readonly _cfg: Idempotency.Cfg

  constructor(
    private readonly _store: Idempotency.Store,
    private readonly cfg?: Partial<Idempotency.Cfg>,
  ) {
    this._cfg = {
      ttlMs: this.cfg?.ttlMs ?? DEFAULT_IDEMPOTENCY_CONFIG.ttlMs,
      headerName: this.cfg?.headerName ?? DEFAULT_IDEMPOTENCY_CONFIG.headerName,
      pollTimeoutMs: this.cfg?.pollTimeoutMs ?? DEFAULT_IDEMPOTENCY_CONFIG.pollTimeoutMs,
    }
    // A NaN ttl reached the stores, which each swapped in a minute of their own. A NaN poll answered every
    // concurrent retry 409 without waiting, and an infinite one never answered once the originator died.
    if (!Number.isFinite(this._cfg.ttlMs) || this._cfg.ttlMs <= 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `idempotency: ttlMs must be a finite positive number (got ${this._cfg.ttlMs})`,
      })
    }
    if (!Number.isFinite(this._cfg.pollTimeoutMs) || this._cfg.pollTimeoutMs < 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `idempotency: pollTimeoutMs must be a finite number, 0 or more (got ${this._cfg.pollTimeoutMs})`,
      })
    }
  }

  /** The header a host's middleware reads the key from, so it is configured once. */
  get headerName(): string {
    return this._cfg.headerName
  }

  /** `executor` runs once, and every repeat of `key` within `ttlMs` is answered from the cached response.
   *  An executor that fails - by throwing, or by answering 5xx - caches nothing and releases the key, so
   *  the retry the client makes with that same key runs for real. Pass `fingerprint`, a hash of the method,
   *  path and body, and a repeat whose fingerprint differs is answered 422 instead of another request's
   *  response. */
  async handle(
    key: string,
    ctx: TenantContext,
    executor: () => Promise<Idempotency.CachedResponse>,
    opts: { identityId?: string; fingerprint?: string } = {},
  ): Promise<Idempotency.CachedResponse> {
    // Skipped without a key, and for a hostile-sized one: a multi-MB Idempotency-Key header would bloat the
    // store and every read of it.
    if (typeof key !== 'string' || key.length === 0 || key.length > 256) {
      return executor()
    }
    // Scoped by identity, so one authenticated caller's cached response is never replayed to another.
    // SECURITY: with no `identityId` every anonymous caller shares the '_anon' bucket, and the key is
    // then the only thing authorising the replay - a bearer credential.
    const scopedKey = `${opts.identityId ?? '_anon'}::${key}`
    // The IETF idempotency-key draft's answer to a key reused with a different payload.
    const replay = (cached: Idempotency.CachedResponse): Idempotency.CachedResponse =>
      cached.fingerprint === opts.fingerprint
        ? cached
        : { status: 422, body: { error: 'idempotency-key-reused' }, createdAt: new Date() }

    const existing = await orNull(this._store.get(scopedKey, ctx))
    if (existing) return replay(existing)

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
      await this._store.put(
        scopedKey,
        opts.fingerprint === undefined ? response : { ...response, fingerprint: opts.fingerprint },
        this._cfg.ttlMs,
        ctx,
      )
      return response
    }

    // Claim refused, so poll with bounded backoff for the originator's put: executing twice would
    // charge twice or mint two tokens.
    const deadline = Date.now() + this._cfg.pollTimeoutMs
    let delay = 10
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, delay))
      const settled = await orNull(this._store.get(scopedKey, ctx))
      if (settled) return replay(settled)
      delay = Math.min(delay * 2, 250)
    }
    // The originator's process died mid-execution, or the store is unreachable. A 409 beats executing
    // twice. An executor that merely failed has already released the key above, so it is not this.
    return { status: 409, body: { error: 'idempotency-conflict' }, createdAt: new Date() }
  }
}

/** Wrap a store of your own in the facet. */
export function idempotency(store: Idempotency.Store, cfg?: Partial<Idempotency.Cfg>): IdempotencyImpl {
  return new IdempotencyImpl(store, cfg)
}

/** Constructs the idempotency facet over a store. */
export function idempotencyImpl(...args: ConstructorParameters<typeof IdempotencyImpl>): IdempotencyImpl {
  return new IdempotencyImpl(...args)
}
