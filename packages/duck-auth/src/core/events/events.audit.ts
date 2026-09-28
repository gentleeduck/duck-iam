import { AsyncLocalStorage } from 'node:async_hooks'
import { actorId } from '../actor'
import type { Sessions } from '../sessions/sessions.types'
import type { Events } from './events.types'

/** Exhaustive by construction: a newly audited event fails to compile until it's listed. */
const AUDITED_EVENTS: Record<Events.AuditedEvent, true> = {
  'identity.erased': true,
  'identity.impersonated': true,
  'identity.impersonation.ended': true,
  'identity.linked': true,
  'identity.unlinked': true,
  lockout: true,
  'mfa.enrolled': true,
  'mfa.removed': true,
  'org.member.added': true,
  'org.member.removed': true,
  'org.roles.set': true,
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

const _ambient = new AsyncLocalStorage<Events.Envelope | undefined>()

/** Run `fn` with `envelope` on every audited event emitted inside it. `undefined` clears the scope rather
 *  than inheriting the one around it, as `withActor(undefined)` does. */
export function runWithAuditEnvelope<T>(envelope: Events.Envelope | undefined, fn: () => Promise<T>): Promise<T> {
  return _ambient.run(envelope, fn)
}

/** The audit envelope in scope, or `undefined` outside `runWithAuditEnvelope`. */
export function currentAuditEnvelope(): Events.Envelope | undefined {
  return _ambient.getStore()
}

/** The envelope a session's requests carry: its `actingAs` while impersonating, otherwise none. */
export function auditEnvelopeFor(
  session: Pick<Sessions.Me, 'actingAs'> | null | undefined,
): Events.Envelope | undefined {
  return session?.actingAs ? { actingAs: session.actingAs } : undefined
}

function stamp<K extends Events.EventName>(event: K, payload: Events.EventMap[K]): Events.EventMap[K] {
  const sent: Events.EventMap[Events.EventName] = payload
  if (!Object.hasOwn(AUDITED_EVENTS, event) || typeof sent !== 'object' || sent === null) return payload
  if ('audit' in sent && sent.audit !== undefined) return payload
  // Ambient describes the request; the session fallback catches lifecycle events emitted
  // outside any wrap, which is how `impersonate-start` itself arrives.
  const ambient = currentAuditEnvelope() ?? ('session' in sent ? auditEnvelopeFor(sent.session) : undefined)
  // An envelope that named the operator explicitly keeps its own answer; otherwise
  // the actor context supplies it. Without this an audited event records only the
  // subject, so "admin X revoked user Y's session" arrives indistinguishable from
  // "user Y revoked their own".
  const actor = ambient?.actorId ?? actorId() ?? undefined
  if (ambient === undefined && actor === undefined) return payload
  const envelope: Events.Envelope = { ...ambient, ...(actor !== undefined && { actorId: actor }) }
  return { ...payload, audit: envelope }
}

/**
 * Wrap a bus so audited events carry their envelope. It lives here because most emitters
 * have no session in scope (`IdentitiesImpl` emits `signup.completed` without one), and
 * threading a session into every facet to satisfy audit would be worse.
 */
export function withAuditStamping(bus: Events.IBus): Events.IBus {
  const wrapper: Events.IBus = {
    emit: (event, payload) => bus.emit(event, stamp(event, payload)),
    on: (event, handler) => bus.on(event, handler),
  }
  const count = bus.listenerCount
  if (count) wrapper.listenerCount = (event) => count.call(bus, event)
  return wrapper
}
