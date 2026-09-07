/**
 * Bind a request's actor scope. The framework adapters wrap handler execution
 * in this; nothing else in the package did, so `created_by` / `updated_by` /
 * `deleted_by` and `Events.Envelope.actorId` were `null` on every write a
 * request drove, whether or not the request was authenticated.
 */

import type { Anomaly } from '../anomaly/anomaly.types'
import { auditEnvelopeFor, runWithAuditEnvelope } from '../events/events.audit'
import type { Sessions } from '../sessions/sessions.types'
import { withActor } from './actor'

/**
 * The shape {@link withRequestActor} needs off the engine. Structural rather
 * than an `AuthEngine` import: `AuthEngine` constructs the actor module, so
 * naming it here would close a cycle. `csrfGuard` types its engine the same way.
 */
export type ActorResolvable = {
  resolveSession(
    req: { headers: Headers },
    opts?: { requestSnapshot?: Anomaly.RequestSnapshot },
  ): Promise<{ session: Sessions.Me } | null>
}

/**
 * What a wrapper may do beyond binding the actor. Both are absent by default, which keeps the
 * wrapper a pure attribution scope: it resolves a session, binds it, and refuses nothing.
 *
 * `server/generic`'s `requestSecurity` fills this in from a request fingerprint, and that is the
 * only thing that switches the checks on.
 */
export type RequestActorOptions = {
  /**
   * Forwarded to `resolveSession`, which runs the registered anomaly detectors against it. No
   * snapshot means no detectors run - they have nothing to compare the request to.
   */
  requestSnapshot?: Anomaly.RequestSnapshot
  /**
   * Runs once the session is resolved and the actor is bound, before `fn`. Throwing here refuses
   * the request; a write it makes first (revoking the session, say) is attributed to that actor.
   */
  onSession?: (session: Sessions.Me) => void | Promise<void>
}

/**
 * Who a write during this request is attributed to.
 *
 * While impersonating, that is the operator behind `actingAs`, not the account
 * being acted on - the subject is already the row being written, and the point
 * of the column is to name the human accountable for the change. Otherwise it
 * is the session's own identity: "the user did this themselves" is a fact, and
 * a distinct one from the `null` that means no actor was bound at all.
 */
export function actorForSession(session: Pick<Sessions.Me, 'identityId' | 'actingAs'>): string | undefined {
  return session.actingAs?.realIdentityId ?? session.identityId ?? undefined
}

/**
 * Resolve the session, bind the actor + audit envelope, and run `fn` inside both.
 *
 * An anonymous request runs `fn` unbound, and so does one whose session cannot
 * be resolved - an expired or forged cookie on a public route must not become a
 * 500, and refusing it is a guard's job, not this wrapper's. Both cases leave
 * the actor `null`, which is the honest answer: no actor was established. The
 * scope is a default, never a fence - an explicit `withActor` inside `fn` still
 * wins, the same as it does over `setDefaultActorResolver`.
 *
 * Costs one `resolveSession` per request. Composed with a guard that resolves
 * as well, that is two store reads; adapters that already hold a resolved
 * session should call {@link withResolvedActor} instead.
 */
export async function withRequestActor<T>(
  auth: ActorResolvable,
  req: { headers: Headers },
  fn: () => Promise<T>,
  opts: RequestActorOptions = {},
): Promise<T> {
  let session: Sessions.Me | undefined
  try {
    const snapshot = opts.requestSnapshot
    session = (await auth.resolveSession(req, snapshot ? { requestSnapshot: snapshot } : undefined))?.session
  } catch {
    // A session that will not resolve is one no actor can be read from. The
    // request continues unattributed rather than failing here.
  }
  if (session === undefined) return fn()
  return withResolvedActor(session, fn, opts)
}

/**
 * {@link withRequestActor} for a caller that has already resolved the session.
 *
 * `opts.onSession` runs inside the scope rather than before it, so a check that writes - a
 * hijack policy revoking the session, say - is attributed to the same actor as the handler
 * would have been, instead of landing unattributed.
 */
export function withResolvedActor<T>(
  session: Sessions.Me,
  fn: () => Promise<T>,
  opts: Pick<RequestActorOptions, 'onSession'> = {},
): Promise<T> {
  return Promise.resolve(
    withActor(actorForSession(session), () =>
      runWithAuditEnvelope(auditEnvelopeFor(session), async () => {
        await opts.onSession?.(session)
        return fn()
      }),
    ),
  )
}
