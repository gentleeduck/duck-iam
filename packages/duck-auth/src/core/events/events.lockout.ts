import { AuthError } from '~/core/errors'
import { isFiniteNumber } from '~/core/predicates/predicates'
import type { Limiter } from '~/limiters'
import type { Events } from './events.types'

/** Just enough bus to emit one event. Not `Events.IBus`: providers hold `Provider.Events`, a deliberately loose
 *  `emit(string, unknown)` that keeps the provider surface from importing the event map. Both satisfy this, and
 *  pinning the event name here still checks the payload against `EventMap['lockout']` at every call site. */
type LockoutBus = {
  emit(event: 'lockout', payload: Events.EventMap['lockout']): Promise<void>
}

/** Turns a spent rate-limit bucket into the refusal and the signal. Every limiter guard goes through here,
 *  so `strict()`'s requirement that something subscribe to `lockout` is a check with an event behind it. A
 *  caller holding an identity passes it and the event names a subject; one that does not passes `null` and
 *  only the refusal happens - `events` may be `null` too, for a guard with no bus in reach, since without
 *  a subject there is nothing to emit either way.
 *  WARN: `retryAfter` floors at 1, since a `Retry-After: 0` tells a client to retry immediately, from the
 *  guard whose whole purpose is to say do not. */
export async function refuseRateLimited(
  events: LockoutBus | null,
  limited: Limiter.Result,
  identityId: string | null,
): Promise<never> {
  // SECURITY: read `resetAt` defensively. `.getTime()` on a non-Date throws, which turned the 429 into a 500
  // and dropped the limit; falling back to "now" still refuses, it only degrades the hint.
  const raw = limited.resetAt instanceof Date ? limited.resetAt.getTime() : limited.resetAt
  const until = isFiniteNumber(raw) ? raw : Date.now()
  if (events !== null && identityId !== null && identityId.length > 0) {
    await events.emit('lockout', { identityId, until })
  }
  throw new AuthError('AUTH_RATE_LIMITED', {
    retryAfter: Math.max(1, Math.ceil((until - Date.now()) / 1000)),
  })
}
