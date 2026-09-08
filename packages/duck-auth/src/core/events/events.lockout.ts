import { isFiniteNumber } from '~/core/credentials/credentials'
import { AuthError } from '~/core/errors'
import type { Limiter } from '~/limiters'
import type { Events } from './events.types'

/**
 * Turn a spent rate-limit bucket into the refusal *and* the signal.
 *
 * `strict()` refuses to boot production unless something subscribes to
 * `lockout`, and nothing in the library ever emitted it: every one of the eight
 * limiter guards computed a `Retry-After`, threw `AUTH_RATE_LIMITED`, and told
 * nobody. Operators were made to wire a handler for an event that could not
 * arrive, which is worse than no check at all - it reads as coverage.
 *
 * So the throw and the emit live in one place. A caller that has an identity in
 * hand passes it and the event names a subject; a caller that does not passes
 * `null` and only the refusal happens. `lockout` carries `{ identityId, until }`
 * and nothing else, so an emit without a subject would be a page an operator
 * cannot act on - "something, somewhere, is being hammered".
 *
 * The floor on `retryAfter` is 1, not 0. Eight of the nine sites used
 * `Math.max(0, …)`, which hands a client `Retry-After: 0` for the last fraction
 * of a second of a window - an instruction to retry immediately, from the guard
 * whose entire purpose is to say do not.
 */
/**
 * Just enough bus to emit one event.
 *
 * Not `Events.IBus`: providers hold `Provider.Events`, a deliberately loose
 * `emit(string, unknown)` that keeps the provider surface from importing the
 * event map. Both satisfy this, and pinning the event name here means the
 * payload is still checked against `EventMap['lockout']` at every call site.
 */
type LockoutBus = {
  emit(event: 'lockout', payload: Events.EventMap['lockout']): Promise<void>
}

export async function refuseRateLimited(
  events: LockoutBus,
  limited: Limiter.Result,
  identityId: string | null,
): Promise<never> {
  // An adapter that returns a broken `resetAt` used to crash the guard:
  // `.getTime()` on a non-Date throws a TypeError, so the caller saw a 500
  // instead of a 429 and the limit did not apply. Read it defensively and fall
  // back to "now" - the request is still refused, only the hint degrades.
  const raw = limited.resetAt instanceof Date ? limited.resetAt.getTime() : limited.resetAt
  const until = isFiniteNumber(raw) ? raw : Date.now()
  if (identityId !== null && identityId.length > 0) {
    await events.emit('lockout', { identityId, until })
  }
  throw new AuthError('AUTH_RATE_LIMITED', {
    retryAfter: Math.max(1, Math.ceil((until - Date.now()) / 1000)),
  })
}
