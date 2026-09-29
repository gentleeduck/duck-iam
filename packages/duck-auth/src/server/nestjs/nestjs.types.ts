import type { Identities } from '~/core/identities/identities.types'

/** The Nest request surface the adapter touches. */
export namespace NestAdapter {
  /** The Nest request fields the adapter reads. */
  export type Request = {
    method: string
    /** Resolved by the host framework against its own proxy trust, never read from a header here. */
    ip?: string
    headers: Record<string, string | string[] | undefined>
    /** The identity duck-auth resolved. The session is `@CurrentSession()`'s: `req.session` is left to the
     *  host's session middleware. */
    identity: Identities.Me | null
  }

  /** A Nest guard. */
  export type Guard = {
    /** Whether the request may reach the handler. */
    canActivate(context: NestAdapter.NestExecutionContextLike): Promise<boolean>
  }

  /** The part of Nest's `ExecutionContext` the guard reads. */
  export type NestExecutionContextLike = {
    switchToHttp(): { getRequest(): NestAdapter.Request }
  }
}
