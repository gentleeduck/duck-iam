/**
 * Koa adapter. Koa is Node-native and uses ctx.req / ctx.request, so
 * the adapter translates between Web-Fetch responses (from
 * executeIntents) and Koa's ctx response API.
 *
 * Mount each handler:
 *
 *   router.post('/auth/signin',  koaSignIn(auth))
 *   router.post('/auth/signout', koaSignOut(auth))
 *   router.get('/auth/session',  koaSession(auth))
 *   router.post('/auth/providers/:id/begin', koaProviderBegin(auth))
 */

import type { AuthRoot } from '../../core/auth'
import {
  errorToHttp,
  executeIntents,
  extractSetCookies,
  nodeHeadersToFetch,
  parseProviderBeginBody,
  parseSignInBody,
} from '../generic'

const toFetchHeaders: (headers: KoaAdapter.IContext['request']['headers']) => Headers = nodeHeadersToFetch

/**
 * Forward a Web Fetch `Response` (from executeIntents) onto a Koa
 * ctx. Set-Cookie multiplicity preserved by using `append()` when the
 * Koa version supports it; falls back to `set()` with a string-array.
 */
async function forward(response: Response, ctx: KoaAdapter.IContext): Promise<void> {
  ctx.status = response.status
  const cookies = extractSetCookies(response)
  if (cookies.length > 0) {
    if (ctx.append) {
      for (const c of cookies) ctx.append('set-cookie', c)
    } else {
      ctx.set('set-cookie', cookies)
    }
  }
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') return
    ctx.set(key, value)
  })
  ctx.body = response.body ? await response.text() : ''
}

function handleError(err: unknown, ctx: KoaAdapter.IContext): void {
  const { status, body } = errorToHttp(err)
  ctx.status = status
  ctx.set('content-type', 'application/json; charset=utf-8')
  ctx.body = JSON.stringify(body)
}

/**
 * Koa handler for the sign-in route.
 */
export function koaSignIn(auth: AuthRoot): KoaAdapter.IHandler {
  return async (ctx) => {
    try {
      const parsed = parseSignInBody(ctx.request.body)
      if (!parsed) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), ctx)
      }
      const result = await auth.flows.signIn(parsed)
      await forward(executeIntents(result.intents), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/**
 * Koa handler for sign-out.
 */
export function koaSignOut(auth: AuthRoot): KoaAdapter.IHandler {
  return async (ctx) => {
    try {
      const sid = auth.transport.extract({ headers: toFetchHeaders(ctx.request.headers) })
      if (!sid) {
        await forward(executeIntents(auth.transport.revoke()), ctx)
        return
      }
      const { intents } = await auth.flows.signOut(sid)
      await forward(executeIntents(intents), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/**
 * Koa handler for the session-introspection route.
 */
export function koaSession(auth: AuthRoot): KoaAdapter.IHandler {
  return async (ctx) => {
    try {
      const resolved = await auth.resolveSession({ headers: toFetchHeaders(ctx.request.headers) })
      ctx.status = 200
      ctx.set('content-type', 'application/json; charset=utf-8')
      ctx.body = JSON.stringify(
        resolved ? { session: resolved.session, identity: resolved.identity } : { session: null, identity: null },
      )
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/**
 * Koa handler for the per-provider begin step.
 */
export function koaProviderBegin(auth: AuthRoot): KoaAdapter.IHandler {
  return async (ctx) => {
    try {
      const id = ctx.params?.id
      if (!id) {
        await forward(executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }]), ctx)
        return
      }
      const body = parseProviderBeginBody(ctx.request.body)
      if (body === null) {
        await forward(executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), ctx)
        return
      }
      const intents = await auth.flows.beginProvider(id, body)
      await forward(executeIntents(intents), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/**
 * Namespace merge for `KoaAdapter`.
 */
export namespace KoaAdapter {
  export type IHandler = (ctx: KoaAdapter.IContext) => Promise<void>

  export interface IContext {
    request: {
      method: string
      url: string
      headers: Record<string, string | string[] | undefined>
      body?: unknown
    }
    params?: Record<string, string>
    status: number
    body: unknown
    set(field: string, value: string | string[]): void
    append?(field: string, value: string | string[]): void
  }
}
