/**
 * The three things every channel needs around the provider call it makes, in one place rather than
 * six: a budget, a deadline, and one retry of a failure that might not repeat.
 */

import { type Answer, answer } from '~/core/answer'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import type { Limiter } from '~/limiters/limiters.types'
import type { Channel } from './channels.types'

const TIMEOUT_DEFAULT_MS = 10_000
/** `setTimeout` overflows past this and silently uses 1ms instead, which deadlines every send at once. */
const TIMEOUT_MAX_MS = 2_147_483_647
const RETRIES_DEFAULT = 2
const RETRY_BASE_MS = 200
/** The doubling backoff already spends over three minutes here; past it a send outlives any request. */
const RETRIES_MAX = 10

export namespace ChannelGuard {
  /** What every channel's `Cfg` extends, so the knobs are declared once and named the same. */
  export interface Cfg {
    /** Ceiling on one provider call, in ms. Default 10000. Zero disables the deadline. */
    timeoutMs?: number
    /** Retries after the first attempt. Default 2. Zero sends exactly once. */
    retries?: number
    /** Budget consulted once per send, before the template is even resolved. */
    limiter?: Limiter.Me
    /** Bucket the send falls in. Default is one bucket per channel per tenant. */
    limiterKey?: (input: Channel.SendInput) => string
  }
}

export class ChannelGuard {
  private readonly _timeoutMs: number
  private readonly _retries: number

  constructor(
    private readonly _id: string,
    private readonly _cfg: ChannelGuard.Cfg,
  ) {
    this._timeoutMs = _cfg.timeoutMs ?? TIMEOUT_DEFAULT_MS
    this._retries = _cfg.retries ?? RETRIES_DEFAULT
    // SECURITY: the ladder `AuthWebhookDeliverer` had, on the path password resets and magic links take.
    // `tries <= NaN` is false on the first test, so the loop never runs, `call` is never made and the
    // `throw last` below throws `undefined` - a send that never happened, reported as nothing an error
    // mapper can render. Infinity retries forever, and `RETRY_BASE_MS * 2 ** tries` overflows `setTimeout`
    // into ~1ms, so the ladder becomes a tight loop against the provider. A `timeoutMs` that is not a
    // number skips the `<= 0` branch that disables the deadline and reaches `setTimeout` anyway, which
    // fires almost immediately: every send aborts before it leaves.
    if (!Number.isFinite(this._retries) || this._retries < 0 || this._retries > RETRIES_MAX) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `${_id}: retries must be a number between 0 and ${RETRIES_MAX} (got ${this._retries})`,
      })
    }
    if (!Number.isFinite(this._timeoutMs) || this._timeoutMs < 0 || this._timeoutMs > TIMEOUT_MAX_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `${_id}: timeoutMs must be a number between 0 and ${TIMEOUT_MAX_MS} (got ${this._timeoutMs})`,
      })
    }
  }

  /** Resolves while there is budget, and rejects `AUTH_RATE_LIMITED` once it is spent. A guard with no
   *  limiter has no budget to spend, so it always resolves. */
  spend(input: Channel.SendInput): Answer.Me<void> {
    return answer(async () => {
      if (!this._cfg.limiter) return
      const key = this._cfg.limiterKey?.(input) ?? `channel:${this._id}:${input.tenant.tenantId ?? '-'}`
      const result = await this._cfg.limiter.consume(key)
      // Through the shared refusal, which reads `resetAt` defensively: `Limiter.Me` is the host's to
      // implement, and one deserialising from redis hands back epoch milliseconds, on which the
      // `.getTime()` this used to call threw. No bus here and no subject to name - a send is refused by
      // channel and tenant, not by identity.
      if (!result.ok) await refuseRateLimited(null, result, null)
    })
  }

  /** One provider call, under a deadline, retried while the clock and the budget of tries allow. */
  async attempt<T>(call: () => Promise<T>): Promise<T> {
    let last: unknown
    for (let tries = 0; tries <= this._retries; tries++) {
      try {
        return await this._deadline(call())
      } catch (err) {
        last = err
        if (tries === this._retries) break
        await new Promise((resolve) => setTimeout(resolve, RETRY_BASE_MS * 2 ** tries))
      }
    }
    throw last
  }

  private async _deadline<T>(call: Promise<T>): Promise<T> {
    if (this._timeoutMs <= 0) return call
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      return await Promise.race([
        call,
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error(`${this._id}: provider did not answer within ${this._timeoutMs}ms`)),
            this._timeoutMs,
          )
        }),
      ])
    } finally {
      if (timer) clearTimeout(timer)
    }
  }
}
