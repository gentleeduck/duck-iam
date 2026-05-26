/**
 * @packageDocumentation
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { AuthRoot } from '../../core/auth'
import { AuthErrorObject } from '../../core/errors'
import type { Identity } from '../../core/types/identity'
import type { Session } from '../../core/types/session'
import { executeIntents } from '../generic'

/**
 * Narrow subset of NestJS request the adapter touches; works for both
 * Express + Fastify Nest platforms.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface NestLikeRequest {
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

/**
 * Narrow subset of NestJS reply. Express + Fastify both satisfy
 * `status(n).set(k,v).send(body)`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface NestLikeReply {
  status(code: number): NestLikeReply
  setHeader?(name: string, value: string | string[]): NestLikeReply
  set?(name: string, value: string | string[]): NestLikeReply
  send(body: unknown): unknown
}

export type NestAuthHandler = (req: NestLikeRequest, reply: NestLikeReply) => Promise<unknown>

/**
 * NestJS guard contract subset. Apps wrap `makeAuthGuard(auth)` in a
 * proper `@Injectable()` class when they need Nest DI plumbing.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface NestLikeGuard {
  canActivate(context: NestExecutionContextLike): Promise<boolean>
}

export interface NestExecutionContextLike {
  switchToHttp(): { getRequest<T = NestLikeRequest>(): T }
}

function toFetchHeaders(headers: NestLikeRequest['headers']): Headers {
  const h = new Headers()
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue
    if (Array.isArray(v)) {
      for (const item of v) h.append(k, String(item))
    } else {
      h.set(k, String(v))
    }
  }
  return h
}

async function forward(response: Response, reply: NestLikeReply): Promise<unknown> {
  reply.status(response.status)
  const setCookies = (response.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie
    ? (response.headers as Headers & { getSetCookie: () => string[] }).getSetCookie()
    : []
  for (const cookie of setCookies) {
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

function handleError(err: unknown, reply: NestLikeReply): unknown {
  if (err instanceof AuthErrorObject) {
    reply.status(err.status)
    if (reply.setHeader) reply.setHeader('content-type', 'application/json; charset=utf-8')
    return reply.send(JSON.stringify(err.toJSON()))
  }
  reply.status(500)
  if (reply.setHeader) reply.setHeader('content-type', 'application/json; charset=utf-8')
  return reply.send(JSON.stringify({ code: 'AUTH/MISCONFIGURED', detail: 'internal error' }))
}

/**
 * Nest handler for the sign-in route.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function nestSignIn(auth: AuthRoot): NestAuthHandler {
  return async (req, reply) => {
    try {
      const body = (req.body ?? {}) as { providerId?: string; input?: unknown }
      if (!body.providerId) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const result = await auth.flows.signIn({
        providerId: body.providerId,
        input: body.input ?? {},
      })
      return forward(executeIntents(result.intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Nest handler for sign-out.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function nestSignOut(auth: AuthRoot): NestAuthHandler {
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function nestSession(auth: AuthRoot): NestAuthHandler {
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function nestProviderBegin(auth: AuthRoot): NestAuthHandler {
  return async (req, reply) => {
    try {
      const id = req.params?.id
      if (!id) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }]), reply)
      }
      const intents = await auth.flows.beginProvider(id, (req.body ?? {}) as unknown)
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function makeAuthGuard(auth: AuthRoot, opts: { required?: boolean } = {}): NestLikeGuard {
  const required = opts.required ?? true
  return {
    async canActivate(ctx) {
      const req = ctx.switchToHttp().getRequest<NestLikeRequest>()
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace NestAdapter {
  /** Alias for `NestAuthHandler`. */
  export type IHandler = NestAuthHandler
  /** Alias for `NestLikeRequest`. */
  export type IRequest = NestLikeRequest
  /** Alias for `NestLikeReply`. */
  export type IReply = NestLikeReply
  /** Alias for `NestLikeGuard`. */
  export type IGuard = NestLikeGuard
  /** Alias for the flat `NestExecutionContextLike` type. */
  export type INestExecutionContextLike = NestExecutionContextLike
}
