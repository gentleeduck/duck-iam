import type { Anomaly } from '~/core/anomaly/anomaly.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/** The actor scope, the resolver that fills it, and what a request wrapper may do while binding one. */
export namespace Actor {
  /** Fills the `created_by` / `updated_by` / `deleted_by` columns. Undefined leaves them NULL. */
  export interface Context {
    /** Opaque - a user id, a service account, `system` - and written verbatim, never resolved. */
    actorId?: string
  }

  /** The process-wide fallback. `null` or `undefined` means no actor, not a broken lookup. */
  export type Resolver = () => string | null | undefined

  /** As much of `AuthEngine` as `withRequestActor` needs; structural, so this module imports no engine. */
  export type Resolvable = {
    resolveSession(
      req: { headers: Headers },
      opts?: { requestSnapshot?: Anomaly.RequestSnapshot },
    ): Promise<{ session: Sessions.Me; anomaly?: Anomaly.Result }>
  }

  /** What a wrapper may do beyond binding the actor; `server/generic`'s `requestSecurity` fills them in. */
  export type RequestOptions = {
    /** Forwarded to `resolveSession`. No snapshot means no detector runs, having nothing to compare. */
    requestSnapshot?: Anomaly.RequestSnapshot
    /** Runs inside the scope before `fn`. Throwing refuses the request; a write it made first is attributed. */
    onSession?: (session: Sessions.Me, anomaly?: Anomaly.Result) => void | Promise<void>
  }
}
