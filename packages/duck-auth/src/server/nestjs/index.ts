import type { ArgumentsHost, ExceptionFilter, ExecutionContext } from '@nestjs/common'
import { Catch, createParamDecorator } from '@nestjs/common'
import type { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import type { Session } from '~/core/sessions/sessions.types'
import type { Identity } from '~/core/types/identity'
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

export function nestSignIn(auth: AuthEngine): NestAdapter.Handler {
  return async (req, reply) => {
    try {
      const parsed = parseSignInBody(req.body)
      if (!parsed) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }]), reply)
      }
      const result = await auth.flows.signIn(parsed)
      return forward(executeIntents(result.intents), reply)
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

export function nestSignOut(auth: AuthEngine): NestAdapter.Handler {
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

export function nestProviderBegin(auth: AuthEngine): NestAdapter.Handler {
  return async (req, reply) => {
    try {
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

export function makeGuard(auth: AuthEngine, opts: { required?: boolean } = {}): NestAdapter.Guard {
  const required = opts.required ?? true
  return {
    async canActivate(ctx) {
      const req = ctx.switchToHttp().getRequest<NestAdapter.Request>()
      const resolved = await auth.resolveSession({ headers: toFetchHeaders(req.headers) })
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

export const DUCK_AUTH_TOKEN = 'DUCK_AUTH'

@Catch(AuthError)
export class NestExceptionFilter implements ExceptionFilter {
  catch(err: AuthError, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<{ status(code: number): { json(body: unknown): void } }>()
    res.status(err.status).json(err.toJSON())
  }
}

export const CurrentSession = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): Session.Me | undefined =>
    ctx.switchToHttp().getRequest<{ session?: Session.Me }>().session,
)

export const CurrentIdentity = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): Identity.Me | null | undefined =>
    ctx.switchToHttp().getRequest<{ identity?: Identity.Me | null }>().identity,
)

export type { NestAdapter } from './nestjs.types'
