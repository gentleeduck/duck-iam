/** Binds a request's actor scope, which is what fills `created_by` / `updated_by` / `deleted_by` and
 *  `Events.Envelope.actorId`. The framework adapters wrap handler execution in it. */

import type { Anomaly } from '../anomaly/anomaly.types'
import { orNull } from '../answer'
import { auditEnvelopeFor, runWithAuditEnvelope } from '../events/events.audit'
import type { Sessions } from '../sessions/sessions.types'
import { withActor } from './actor'

/**  which would close a cycle; `csrfGuard` types its engine the same way. */
export type ActorResolvable = {
  resolveSession(
    req: { headers: Headers },
    opts?: { requestSnapshot?: Anomaly.RequestSnapshot },
  ): Promise<{ session: Sessions.Me }>
}

/** What a wrapper may do beyond binding the actor. Both absent by default, which keeps it a pure
 *  attribution scope that refuses nothing; `server/generic`'s `requestSecurity` is what fills them in. */
export type RequestActorOptions = {
  /** Forwarded to `resolveSession`, which runs the registered anomaly detectors against it. No snapshot
   *  means no detectors run, having nothing to compare the request to. */
  requestSnapshot?: Anomaly.RequestSnapshot
  /**
   * Runs once the session is resolved and the actor is bound, before `fn`. Throwing here refuses
   * the request; a write it makes first (revoking the session, say) is attributed to that actor.
   */
  onSession?: (session: Sessions.Me) => void | Promise<void>
}

/** Who a write during this request is attributed to. While impersonating that is the operator behind
 *  `actingAs`, not the account acted on, since the column names the human accountable. Otherwise the
 *  session's own identity, which is a distinct fact from the `null` that means no actor was bound. */
export function actorForSession(session: Pick<Sessions.Me, 'identityId' | 'actingAs'>): string | undefined {
  return session.actingAs?.realIdentityId ?? session.identityId ?? undefined
}

/**
 * Resolves the session, binds the actor and audit envelope, and runs `fn` inside both. An anonymous
 * request runs `fn` unbound, and so does one whose session will not resolve, leaving the actor `null`:
 * refusing an expired or forged cookie is a guard's job, not this wrapper's. The scope is a default,
 * never a fence, and an explicit `withActor` inside `fn` still wins.
 *
 * PERF: one `resolveSession` per request. A caller that already holds one should use
 * {@link withResolvedActor} instead of paying for a second read.
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
    const resolved = auth.resolveSession(req, snapshot ? { requestSnapshot: snapshot } : undefined)
    session = (await orNull(resolved))?.session
  } catch {
    // An anonymous request is `orNull`'s null above; this is the rest - a store that is down, or a session
    // that outlived its identity. Both leave the request unattributed rather than failing here, which is
    // what this wrapper did before either was distinguishable.
  }
  if (session === undefined) return fn()
  return withResolvedActor(session, fn, opts)
}

/** {@link withRequestActor} for a caller that already resolved the session. `opts.onSession` runs
 *  inside the scope, so a check that writes, a hijack policy revoking the session say, is attributed
 *  rather than landing anonymous. */
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
