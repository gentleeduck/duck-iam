import type { Anomaly } from '../anomaly/anomaly.types'
import { orNull } from '../answer'
import { auditEnvelopeFor, runWithAuditEnvelope } from '../events/events.audit'
import type { Sessions } from '../sessions/sessions.types'
import { withActor } from './actor'
import type { Actor } from './actor.types'

/** Resolves the session, binds the actor and the audit envelope, and runs `fn` inside both.
 *  PERF: one `resolveSession` per request; a caller holding one uses {@link withResolvedActor}. */
export async function withRequestActor<T>(
  auth: Actor.Resolvable,
  req: { headers: Headers },
  fn: () => Promise<T>,
  opts: Actor.RequestOptions = {},
): Promise<T> {
  // SECURITY: no catch. `orNull` answers null for every code meaning "no session", so an anonymous or
  // forged request runs as nobody; a store that is down and a session outliving its identity still throw.
  const resolved = await orNull(auth.resolveSession(req, { requestSnapshot: opts.requestSnapshot }))
  return withResolvedActor(resolved?.session ?? null, fn, opts, resolved?.anomaly)
}

/** {@link withRequestActor} for a caller that already resolved the session, or found none. `opts.onSession`
 *  runs inside the scope, so a check that writes is attributed rather than landing anonymous. */
export function withResolvedActor<T>(
  session: Sessions.Me | null,
  fn: () => Promise<T>,
  opts: Pick<Actor.RequestOptions, 'onSession'> = {},
  anomaly?: Anomaly.Result,
): Promise<T> {
  // The operator while impersonating, since the column names the human accountable.
  const actor = session?.actingAs?.realIdentityId ?? session?.identityId ?? undefined
  // SECURITY: bound without a session too, or an anonymous request inherits the actor and the audit
  // envelope of the scope the server was started inside.
  return withActor(actor, () =>
    runWithAuditEnvelope(auditEnvelopeFor(session), async () => {
      if (session) {
        await opts.onSession?.(session, anomaly)
        // After the checks, so a request they refuse teaches the detectors nothing.
        await anomaly?.admit()
      }
      return fn()
    }),
  )
}
