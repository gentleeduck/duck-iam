import type { Anomaly } from '~/core/anomaly/anomaly.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/** The resolver behind the actor scope, and what a request wrapper may do while binding one. */
export namespace Actor {
  /** The process-wide fallback. `null` or `undefined` means no actor, not a broken lookup. */
  export type Resolver = () => string | null | undefined

  /** As much of `AuthEngine` as `withRequestActor` needs; structural, so this module imports no engine. */
  export type Resolvable = {
    /** Resolves the request's session, as `AuthEngine.resolveSession` does. */
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
