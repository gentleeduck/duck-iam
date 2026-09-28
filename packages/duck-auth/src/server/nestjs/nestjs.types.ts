import type { Identities } from '~/core/identities/identities.types'

/** The Nest request and response surface the adapter touches. */
export namespace NestAdapter {
  /** A route handler. */
  export type Handler = (req: NestAdapter.Request, reply: NestAdapter.Response) => Promise<unknown>

  /** The Nest request fields the adapter reads. */
  export type Request = {
    method: string
    url?: string
    /** Resolved by the host framework against its own proxy trust, never read from a header here. */
    ip?: string
    headers: Record<string, string | string[] | undefined>
    body?: unknown
    params?: Record<string, string>
    /** The identity duck-auth resolved. The session is `@CurrentSession()`'s: `req.session` is left to the
     *  host's session middleware. */
    identity: Identities.Me | null
  }

  /** The Express response `@nestjs/platform-express` hands a handler. A Fastify reply has no `setHeader`. */
  export type Response = {
    status(code: number): NestAdapter.Response
    setHeader(name: string, value: string | string[]): NestAdapter.Response
    send(body: unknown): unknown
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
