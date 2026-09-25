import type { Anomaly } from '../anomaly/anomaly.types'
import { orNull } from '../answer'
import { auditEnvelopeFor, runWithAuditEnvelope } from '../events/events.audit'
import type { Sessions } from '../sessions/sessions.types'
import { withActor } from './actor'
import type { Actor } from './actor.types'

/** The operator behind `actingAs` while impersonating, since the column names the human accountable,
 *  otherwise the session's own identity. */
export function actorForSession(session: Pick<Sessions.Me, 'identityId' | 'actingAs'>): string | undefined {
  return session.actingAs?.realIdentityId ?? session.identityId ?? undefined
}

/** Resolves the session, binds the actor and the audit envelope, and runs `fn` inside both.
 *  PERF: one `resolveSession` per request; a caller holding one uses {@link withResolvedActor}. */
export async function withRequestActor<T>(
  auth: Actor.Resolvable,
  req: { headers: Headers },
  fn: () => Promise<T>,
  opts: Actor.RequestOptions = {},
): Promise<T> {
  const snapshot = opts.requestSnapshot
  // SECURITY: no catch. `orNull` answers null for every code meaning "no session", so an anonymous or
  // forged request runs unbound; a store that is down and a session outliving its identity still throw.
  const resolved = await orNull(auth.resolveSession(req, snapshot ? { requestSnapshot: snapshot } : undefined))
  if (!resolved) return fn()
  return withResolvedActor(resolved.session, fn, opts, resolved.anomaly)
}

/** {@link withRequestActor} for a caller that already resolved the session. `opts.onSession` runs inside
 *  the scope, so a check that writes is attributed rather than landing anonymous. */
export function withResolvedActor<T>(
  session: Sessions.Me,
  fn: () => Promise<T>,
  opts: Pick<Actor.RequestOptions, 'onSession'> = {},
  anomaly?: Anomaly.Result,
): Promise<T> {
  return withActor(actorForSession(session), () =>
    runWithAuditEnvelope(auditEnvelopeFor(session), async () => {
      await opts.onSession?.(session, anomaly)
      return fn()
    }),
  )
}
