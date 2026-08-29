import { AsyncLocalStorage } from 'node:async_hooks'
import type { Sessions } from '../sessions/sessions.types'
import type { Events } from './events.types'

/** Exhaustive by construction: a newly audited event fails to compile until it's listed. */
const AUDITED_EVENTS: Record<Events.AuditedEvent, true> = {
  'identity.linked': true,
  'identity.merged': true,
  lockout: true,
  'mfa.enrolled': true,
  'mfa.removed': true,
  'recovery.mfa.escalated': true,
  'recovery.password.completed': true,
  'recovery.password.requested': true,
  'session.created': true,
  'session.revoked': true,
  'session.rotated': true,
  'signin.failed': true,
  'signin.success': true,
  'signup.completed': true,
  suspicious: true,
}

const _ambient = new AsyncLocalStorage<Events.Envelope>()

/**
 * Run `fn` with `envelope` on every audited event emitted inside it. Adapters wrap
 * request handling in this once the session is resolved:
 *
 * ```ts
 * const resolved = await auth.resolveSession(req)
 * return runWithAuditEnvelope(auditEnvelopeFor(resolved?.session), () => handle(req))
 * ```
 *
 * It has to be explicit, because doing it inside `resolveSession` would need
 * `AsyncLocalStorage.enterWith`, which segfaults on Bun 1.3.14-canary. `run()` is fine.
 */
export function runWithAuditEnvelope<T>(envelope: Events.Envelope | undefined, fn: () => Promise<T>): Promise<T> {
  if (envelope === undefined) return fn()
  return _ambient.run(envelope, fn)
}

/** The envelope in effect for the current async context, if any. */
export function currentAuditEnvelope(): Events.Envelope | undefined {
  return _ambient.getStore()
}

/** `undefined` when not impersonating, so the wrap above costs nothing on the hot path. */
export function auditEnvelopeFor(
  session: Pick<Sessions.Me, 'actingAs'> | null | undefined,
): Events.Envelope | undefined {
  return session?.actingAs ? { actingAs: session.actingAs } : undefined
}

function stamp<K extends Events.EventName>(event: K, payload: Events.EventMap[K]): Events.EventMap[K] {
  if (!(event in AUDITED_EVENTS)) return payload
  if (typeof payload !== 'object' || payload === null) return payload
  const p = payload as Events.Stampable
  if (p.audit !== undefined) return payload
  // Ambient describes the request; the session fallback catches lifecycle events emitted
  // outside any wrap, which is how `impersonate-start` itself arrives.
  const envelope = currentAuditEnvelope() ?? (p.session?.actingAs ? { actingAs: p.session.actingAs } : undefined)
  if (envelope === undefined) return payload
  return { ...payload, audit: envelope }
}

/**
 * Wrap a bus so audited events carry their envelope. It lives here because most emitters
 * have no session in scope (`IdentitiesImpl` emits `signup.completed` without one), and
 * threading a session into every facet to satisfy audit would be worse.
 *
 * `listenerCount` must survive the wrap: `AuthEngine.strict()` duck-types it and silently
 * skips its `lockout` gate when it's missing.
 */
export function withAuditStamping(bus: Events.IBus): Events.IBus {
  const wrapper: Events.IBus & { listenerCount?: (event: Events.EventName) => number } = {
    emit: (event, payload) => bus.emit(event, stamp(event, payload)),
    on: (event, handler) => bus.on(event, handler),
  }
  const count = (bus as { listenerCount?: (event: Events.EventName) => number }).listenerCount
  if (typeof count === 'function') {
    wrapper.listenerCount = (event) => count.call(bus, event)
  }
  return wrapper
}
