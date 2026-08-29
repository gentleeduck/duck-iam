import type { ArgumentsHost, ExceptionFilter, ExecutionContext } from '@nestjs/common'
import { Catch, createParamDecorator } from '@nestjs/common'
import type { Csrf } from '~/core/csrf'
import { csrfGuard, verifyCsrf } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import {
  errorToHttp,
  executeIntents,
  extractSetCookies,
  isValidProviderId,
  nodeHeadersToFetch,
  parseProviderBeginBody,
  parseSignInBody,
} from '../generic'

import type { NestAdapter } from './nestjs.types'

const toFetchHeaders: (headers: NestAdapter.Request['headers']) => Headers = nodeHeadersToFetch

async function forward(response: Response, reply: NestAdapter.Response): Promise<unknown> {
  reply.status(response.status)
  const cookies = extractSetCookies(response)
  if (cookies.length > 0) {
    if (reply.setHeader) reply.setHeader('set-cookie', cookies)
    else if (reply.set) reply.set('set-cookie', cookies)
  }
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') return
    if (reply.setHeader) reply.setHeader(key, value)
    else if (reply.set) reply.set(key, value)
  })
  const body = response.body ? await response.text() : ''
  return reply.send(body)
}

function handleError(err: unknown, reply: NestAdapter.Response): never {
  const { status, body } = errorToHttp(err)
  reply.status(status)
  if (reply.setHeader) reply.setHeader('content-type', 'application/json; charset=utf-8')
  reply.send(JSON.stringify(body))
  // rethrow so NestJS exception filter can log to Loki; filter's res.headersSent
  // check prevents double-send
  throw err
}

/** POST sign-in. CSRF-guarded. */
export function nestSignIn(auth: AuthEngine): NestAdapter.Handler {
  return async (req, reply) => {
    try {
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method })
      const parsed = parseSignInBody(req.body)
      if (!parsed) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      // The flow, the store and the columns all take these and the adapter was dropping
      // them, so every session row recorded a device it could not name.
      const result = await auth.flows.signIn({ ...parsed, ...callerOf(req) })
      return forward(executeIntents(result.intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * `req.ip` and nothing else: the host resolves it against its own proxy trust, and reading a
 * forwarded header here would take the value the caller wrote.
 */
function callerOf(req: NestAdapter.Request): { ip?: string; userAgent?: string } {
  const ua = req.headers?.['user-agent']
  return {
    ...(req.ip !== undefined && { ip: req.ip }),
    ...(typeof ua === 'string' && { userAgent: ua }),
  }
}

/** POST sign-out. CSRF-guarded. */
export function nestSignOut(auth: AuthEngine): NestAdapter.Handler {
  return async (req, reply) => {
    try {
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method })
      const sid = auth.transport.extract({ headers: toFetchHeaders(req.headers) })
      if (!sid) return forward(executeIntents(auth.transport.revoke()), reply)
      const { intents } = await auth.flows.signOut(sid)
      return forward(executeIntents(intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

export function nestSession(auth: AuthEngine): NestAdapter.Handler {
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

/** POST provider-begin. CSRF-guarded. */
export function nestProviderBegin(auth: AuthEngine): NestAdapter.Handler {
  return async (req, reply) => {
    try {
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method })
      const id = req.params?.id
      if (!isValidProviderId(id)) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }]), reply)
      }
      const body = parseProviderBeginBody(req.body)
      if (body === null) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const intents = await auth.flows.beginProvider(id, body)
      return forward(executeIntents(intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

/**
 * Auth guard for your own routes. CSRF is checked by default because a
 * cookie-session app mounting only this guard would otherwise have no CSRF
 * defence at all. Pass `csrf: false` only if something upstream already did it.
 */
export function makeGuard(auth: AuthEngine, opts: { required?: boolean; csrf?: boolean } = {}): NestAdapter.Guard {
  const required = opts.required ?? true
  const csrf = opts.csrf ?? true
  return {
    async canActivate(ctx) {
      const req = ctx.switchToHttp().getRequest<NestAdapter.Request>()
      const resolved = await auth.resolveSession({ headers: toFetchHeaders(req.headers) })
      if (csrf) {
        // Reuse the session we just resolved rather than paying a second
        // resolveSession inside csrfGuard.
        verifyCsrf({
          headers: toFetchHeaders(req.headers),
          method: req.method,
          ...(resolved?.session.csrfHash != null && { sessionCsrfHash: resolved.session.csrfHash }),
        })
      }
      if (!resolved) {
        if (required) {
          throw new AuthError('AUTH_UNAUTHENTICATED')
        }
        return true
      }
      req.session = resolved.session
      // Adapter is profile-agnostic; store the resolved identity opaquely.
      req.identity = resolved.identity as NestAdapter.Request['identity']
      return true
    },
  }
}

/** CSRF-only guard, for routes that need the check without the auth gate. */
export function makeCsrfGuard(auth: AuthEngine, opts: Csrf.GuardOptions = {}): NestAdapter.Guard {
  return {
    async canActivate(ctx) {
      const req = ctx.switchToHttp().getRequest<NestAdapter.Request>()
      await csrfGuard(auth, { headers: toFetchHeaders(req.headers), method: req.method }, opts)
      return true
    },
  }
}

export const DUCK_AUTH_TOKEN = 'DUCK_AUTH'

@Catch(AuthError)
export class NestExceptionFilter implements ExceptionFilter {
  catch(err: AuthError, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<{ status(code: number): { json(body: unknown): void } }>()
    res.status(err.status).json(err.toJSON())
  }
}

export const CurrentSession = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): Sessions.Me | undefined =>
    ctx.switchToHttp().getRequest<{ session?: Sessions.Me }>().session,
)

export const CurrentIdentity = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): Identities.Me | null | undefined =>
    ctx.switchToHttp().getRequest<{ identity?: Identities.Me | null }>().identity,
)

export type { NestAdapter } from './nestjs.types'

/** Factory around {@link NestExceptionFilter}, for callers who prefer functions to `new`. */
export function nestExceptionFilter(...args: ConstructorParameters<typeof NestExceptionFilter>): NestExceptionFilter {
  return new NestExceptionFilter(...args)
}
