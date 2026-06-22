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
 *     constructor(@Inject('AUTH_ROOT') private auth: AuthEngine) {}
 *
 *     @Post('signin')
 *     signin(@Req() req, @Res() res) {
 *       return authNestSignIn(this.auth)(req, res)
 *     }
 *
 *     @Get('me')
 *     @UseGuards(authMakeGuard(this.auth))
 *     me(@Req() req) { return (req as any).session }
 *   }
 *   ```
 */

import type { AuthEngine } from '../../core/auth'
import { AuthErrorObject } from '../../core/errors'
import type { AuthIdentity } from '../../core/types/identity'
import type { AuthSession } from '../../core/types/session'
import {
  authErrorToHttp,
  authExecuteIntents,
  authExtractSetCookies,
  authIsValidProviderId,
  authNodeHeadersToFetch,
  authParseProviderBeginBody,
  authParseSignInBody,
} from '../generic'

const toFetchHeaders: (headers: AuthNestAdapter.IRequest['headers']) => Headers = authNodeHeadersToFetch

async function forward(response: Response, reply: AuthNestAdapter.IReply): Promise<unknown> {
  reply.status(response.status)
  for (const cookie of authExtractSetCookies(response)) {
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

function handleError(err: unknown, reply: AuthNestAdapter.IReply): unknown {
  const { status, body } = authErrorToHttp(err)
  reply.status(status)
  if (reply.setHeader) reply.setHeader('content-type', 'application/json; charset=utf-8')
  return reply.send(JSON.stringify(body))
}

/** Nest handler for the sign-in route. */
export function authNestSignIn(auth: AuthEngine): AuthNestAdapter.IHandler {
  return async (req, reply) => {
    try {
      const parsed = authParseSignInBody(req.body)
      if (!parsed) {
        return forward(authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const result = await auth.flows.signIn(parsed)
      return forward(authExecuteIntents(result.intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/** Nest handler for sign-out. */
export function authNestSignOut(auth: AuthEngine): AuthNestAdapter.IHandler {
  return async (req, reply) => {
    try {
      const sid = auth.transport.extract({ headers: toFetchHeaders(req.headers) })
      if (!sid) return forward(authExecuteIntents(auth.transport.revoke()), reply)
      const { intents } = await auth.flows.signOut(sid)
      return forward(authExecuteIntents(intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/** Nest handler for the session-introspection route. */
export function authNestSession(auth: AuthEngine): AuthNestAdapter.IHandler {
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

/** Nest handler for the per-provider begin step. */
export function authNestProviderBegin(auth: AuthEngine): AuthNestAdapter.IHandler {
  return async (req, reply) => {
    try {
      const id = req.params?.id
      if (!authIsValidProviderId(id)) {
        return forward(authExecuteIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }]), reply)
      }
      const body = authParseProviderBeginBody(req.body)
      if (body === null) {
        return forward(authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const intents = await auth.flows.beginProvider(id, body)
      return forward(authExecuteIntents(intents), reply)
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
 *     constructor(@Inject('AUTH_ROOT') private auth: AuthEngine) {}
 *     canActivate = authMakeGuard(this.auth).canActivate
 *   }
 *   ```
 */
export function authMakeGuard(auth: AuthEngine, opts: { required?: boolean } = {}): AuthNestAdapter.IGuard {
  const required = opts.required ?? true
  return {
    async canActivate(ctx) {
      const req = ctx.switchToHttp().getRequest<AuthNestAdapter.IRequest>()
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

export namespace AuthNestAdapter {
  export type IHandler = (req: AuthNestAdapter.IRequest, reply: AuthNestAdapter.IReply) => Promise<unknown>

  export interface IRequest {
    method: string
    url?: string
    headers: Record<string, string | string[] | undefined>
    body?: unknown
    params?: Record<string, string>
    /** Mutation slot for the guard - the resolved session lands here. */
    session?: AuthSession.ISession
    /** Mutation slot for the guard - the resolved identity lands here. */
    identity?: AuthIdentity.IIdentity<unknown> | null
  }

  export interface IReply {
    status(code: number): AuthNestAdapter.IReply
    setHeader?(name: string, value: string | string[]): AuthNestAdapter.IReply
    set?(name: string, value: string | string[]): AuthNestAdapter.IReply
    send(body: unknown): unknown
  }

  export interface IGuard {
    canActivate(context: AuthNestAdapter.INestExecutionContextLike): Promise<boolean>
  }

  export interface INestExecutionContextLike {
    switchToHttp(): { getRequest<T = AuthNestAdapter.IRequest>(): T }
  }
}
