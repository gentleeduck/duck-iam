/**
 * The three things every channel needs around the provider call it makes, in one place rather than
 * six: a budget, a deadline, and one retry of a failure that might not repeat.
 *
 * None of them existed. A provider that accepted the connection and never answered parked a
 * password reset for as long as the socket stayed open; one transient 503 dropped the only copy of
 * a sign-in link; and a loop over `send` was bounded by the provider's own rate limit, which is
 * what toll fraud against an SMS route looks like.
 */

import type { Limiter } from '~/limiters/limiters.types'
import type { Channel } from './channels.types'

const TIMEOUT_DEFAULT_MS = 10_000
const RETRIES_DEFAULT = 2
const RETRY_BASE_MS = 200

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
  }

  /** The refusal to report, or null when there is budget. */
  async spend(input: Channel.SendInput): Promise<string | null> {
    if (!this._cfg.limiter) return null
    const key = this._cfg.limiterKey?.(input) ?? `channel:${this._id}:${input.tenant.tenantId ?? '-'}`
    const result = await this._cfg.limiter.consume(key)
    return result.ok ? null : `${this._id}: send budget exhausted, next at ${result.resetAt.toISOString()}`
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
