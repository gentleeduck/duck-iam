/**
 * NestJS adapter. NestJS controllers receive `Request` + `Response`
 * (Express adapter) OR `FastifyRequest` + `FastifyReply`; this module
 * ships handler factories that work with either via a narrow
 * shape contract, plus a `@AuthGuard()` you can apply to any
 * controller method to enforce `auth.resolveSession`.
 *
 * Mount on a controller:
 *
 *   ```ts
 *   @Controller('auth')
 *   export class AuthController {
 *     constructor(@Inject('AUTH_ROOT') private auth: AuthRoot) {}
 *
 *     @Post('signin')
 *     signin(@Req() req, @Res() res) {
 *       return nestSignIn(this.auth)(req, res)
 *     }
 *
 *     @Get('me')
 *     @UseGuards(makeAuthGuard(this.auth))
 *     me(@Req() req) { return (req as any).session }
 *   }
 *   ```
 */

import type { AuthRoot } from '../../core/auth'
import { AuthErrorObject } from '../../core/errors'
import type { Identity } from '../../core/types/identity'
import type { Session } from '../../core/types/session'
import {
  errorToHttp,
  executeIntents,
  extractSetCookies,
  nodeHeadersToFetch,
  parseProviderBeginBody,
  parseSignInBody,
} from '../generic'

const toFetchHeaders: (headers: NestAdapter.IRequest['headers']) => Headers = nodeHeadersToFetch

async function forward(response: Response, reply: NestAdapter.IReply): Promise<unknown> {
  reply.status(response.status)
  for (const cookie of extractSetCookies(response)) {
    if (reply.setHeader) reply.setHeader('set-cookie', cookie)
    else if (reply.set) reply.set('set-cookie', cookie)
  }
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') return
    if (reply.setHeader) reply.setHeader(key, value)
    else if (reply.set) reply.set(key, value)
  })
  const body = response.body ? await response.text() : ''
  return reply.send(body)
}

function handleError(err: unknown, reply: NestAdapter.IReply): unknown {
  const { status, body } = errorToHttp(err)
  reply.status(status)
  if (reply.setHeader) reply.setHeader('content-type', 'application/json; charset=utf-8')
  return reply.send(JSON.stringify(body))
}

/**
 * Nest handler for the sign-in route.
 */
export function nestSignIn(auth: AuthRoot): NestAdapter.IHandler {
  return async (req, reply) => {
    try {
      const parsed = parseSignInBody(req.body)
      if (!parsed) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const result = await auth.flows.signIn(parsed)
      return forward(executeIntents(result.intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Nest handler for sign-out.
 */
export function nestSignOut(auth: AuthRoot): NestAdapter.IHandler {
  return async (req, reply) => {
    try {
      const sid = auth.transport.extract({ headers: toFetchHeaders(req.headers) })
      if (!sid) return forward(executeIntents(auth.transport.revoke()), reply)
      const { intents } = await auth.flows.signOut(sid)
      return forward(executeIntents(intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Nest handler for the session-introspection route.
 */
export function nestSession(auth: AuthRoot): NestAdapter.IHandler {
  return async (req, reply) => {
    try {
      const resolved = await auth.resolveSession({ headers: toFetchHeaders(req.headers) })
      reply.status(200)
      if (reply.setHeader) reply.setHeader('content-type', 'application/json; charset=utf-8')
      return reply.send(
        JSON.stringify(
          resolved ? { session: resolved.session, identity: resolved.identity } : { session: null, identity: null },
        ),
      )
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Nest handler for the per-provider begin step.
 */
export function nestProviderBegin(auth: AuthRoot): NestAdapter.IHandler {
  return async (req, reply) => {
    try {
      const id = req.params?.id
      if (!id) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }]), reply)
      }
      const body = parseProviderBeginBody(req.body)
      if (body === null) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const intents = await auth.flows.beginProvider(id, body)
      return forward(executeIntents(intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Build a Nest guard that calls `auth.resolveSession` on the request
 * + writes `req.session` + `req.identity`. Returns false (Nest emits
 * 403) when no session resolves; throws AUTH/UNAUTHENTICATED when the
 * caller wants Nest's exception filter to map it.
 *
 * Use:
 *   ```ts
 *   @Injectable()
 *   class DuckAuthGuard {
 *     constructor(@Inject('AUTH_ROOT') private auth: AuthRoot) {}
 *     canActivate = makeAuthGuard(this.auth).canActivate
 *   }
 *   ```
 */
export function makeAuthGuard(auth: AuthRoot, opts: { required?: boolean } = {}): NestAdapter.IGuard {
  const required = opts.required ?? true
  return {
    async canActivate(ctx) {
      const req = ctx.switchToHttp().getRequest<NestAdapter.IRequest>()
      const resolved = await auth.resolveSession({ headers: toFetchHeaders(req.headers) })
      if (!resolved) {
        if (required) {
          throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
        }
        return true
      }
      req.session = resolved.session
      req.identity = resolved.identity
      return true
    },
  }
}

/**
 * Namespace merge for `NestAdapter`.
 */
export namespace NestAdapter {
  export type IHandler = (req: NestAdapter.IRequest, reply: NestAdapter.IReply) => Promise<unknown>

  export interface IRequest {
    method: string
    url?: string
    headers: Record<string, string | string[] | undefined>
    body?: unknown
    params?: Record<string, string>
    /** Mutation slot for the guard - the resolved session lands here. */
    session?: Session.ISession
    /** Mutation slot for the guard - the resolved identity lands here. */
    identity?: Identity.IIdentity<unknown> | null
  }

  export interface IReply {
    status(code: number): NestAdapter.IReply
    setHeader?(name: string, value: string | string[]): NestAdapter.IReply
    set?(name: string, value: string | string[]): NestAdapter.IReply
    send(body: unknown): unknown
  }

  export interface IGuard {
    canActivate(context: NestAdapter.INestExecutionContextLike): Promise<boolean>
  }

  export interface INestExecutionContextLike {
    switchToHttp(): { getRequest<T = NestAdapter.IRequest>(): T }
  }
}
