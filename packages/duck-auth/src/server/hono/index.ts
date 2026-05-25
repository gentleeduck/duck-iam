import type { AuthRoot } from '../../core/auth'
import { AuthErrorObject } from '../../core/errors'
import { executeIntents } from '../generic'

/**
 * Hono adapter. Hono is Web-Fetch native (Request/Response), so the implementation
 * is a thin wrapper around `server/generic.executeIntents`.
 *
 * Apps wire each handler under a route on their Hono app:
 *
 *   app.post('/auth/signin',  honoSignIn(auth))
 *   app.post('/auth/signout', honoSignOut(auth))
 *   app.get('/auth/session',  honoSession(auth))
 *   app.post('/auth/providers/:id/begin', honoProviderBegin(auth))
 */

export type HonoHandler = (ctx: HonoContextLike) => Promise<Response>

export interface HonoContextLike {
  req: {
    method: string
    url: string
    header(name?: string): string | undefined | Record<string, string>
    raw: Request
    json: () => Promise<unknown>
    param(name: string): string | undefined
  }
}

function reqHeaders(ctx: HonoContextLike): Headers {
  return ctx.req.raw.headers
}

export function honoSignIn(auth: AuthRoot): HonoHandler {
  return async (ctx) => {
    try {
      const body = (await ctx.req.json().catch(() => ({}))) as {
        providerId?: string
        input?: unknown
      }
      if (!body.providerId) {
        return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn({
        providerId: body.providerId,
        input: body.input ?? {},
      })
      return executeIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

export function honoSignOut(auth: AuthRoot): HonoHandler {
  return async (ctx) => {
    try {
      const sid = auth.transport.extract({ headers: reqHeaders(ctx) })
      if (!sid) return executeIntents(auth.transport.revoke())
      const { intents } = await auth.flows.signOut(sid)
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

export function honoSession(auth: AuthRoot): HonoHandler {
  return async (ctx) => {
    try {
      const resolved = await auth.resolveSession({ headers: reqHeaders(ctx) })
      const body = resolved
        ? { session: resolved.session, identity: resolved.identity }
        : { session: null, identity: null }
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json; charset=utf-8' },
      })
    } catch (err) {
      return handleError(err)
    }
  }
}

export function honoProviderBegin(auth: AuthRoot): HonoHandler {
  return async (ctx) => {
    try {
      const id = ctx.req.param('id')
      if (!id) {
        return executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }])
      }
      const body = (await ctx.req.json().catch(() => ({}))) as unknown
      const intents = await auth.flows.beginProvider(id, body ?? {})
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

function handleError(err: unknown): Response {
  if (err instanceof AuthErrorObject) {
    return new Response(JSON.stringify(err.toJSON()), {
      status: err.status,
      headers: { 'content-type': 'application/json; charset=utf-8' },
    })
  }
  return new Response(JSON.stringify({ code: 'AUTH/MISCONFIGURED', detail: 'internal error' }), {
    status: 500,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}
