/**
 * @packageDocumentation
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { AuthRoot } from '../../core/auth'
import { AuthErrorObject } from '../../core/errors'
import { executeIntents } from '../generic'

/**
 * Narrow subset of Koa's ctx + request + response surface the adapter
 * touches. Lets us accept Koa contexts without importing koa types as
 * a hard dep.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface KoaLikeContext {
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

/**
 * Koa route-handler shape. Returns void; Koa drains ctx.body itself.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export type KoaAuthHandler = (ctx: KoaLikeContext) => Promise<void>

function toFetchHeaders(headers: KoaLikeContext['request']['headers']): Headers {
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

/**
 * Forward a Web Fetch `Response` (from executeIntents) onto a Koa
 * ctx. Set-Cookie multiplicity preserved by using `append()` when the
 * Koa version supports it; falls back to `set()` with a string-array.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
async function forward(response: Response, ctx: KoaLikeContext): Promise<void> {
  ctx.status = response.status
  const getSetCookie = (response.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie
  const cookies = getSetCookie ? getSetCookie.call(response.headers) : []
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

function handleError(err: unknown, ctx: KoaLikeContext): void {
  if (err instanceof AuthErrorObject) {
    ctx.status = err.status
    ctx.set('content-type', 'application/json; charset=utf-8')
    ctx.body = JSON.stringify(err.toJSON())
    return
  }
  ctx.status = 500
  ctx.set('content-type', 'application/json; charset=utf-8')
  ctx.body = JSON.stringify({ code: 'AUTH/MISCONFIGURED', detail: 'internal error' })
}

/**
 * Koa handler for the sign-in route.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function koaSignIn(auth: AuthRoot): KoaAuthHandler {
  return async (ctx) => {
    try {
      const body = (ctx.request.body ?? {}) as { providerId?: string; input?: unknown }
      if (!body.providerId) {
        return forward(executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), ctx)
      }
      const result = await auth.flows.signIn({
        providerId: body.providerId,
        input: body.input ?? {},
      })
      await forward(executeIntents(result.intents), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/**
 * Koa handler for sign-out.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function koaSignOut(auth: AuthRoot): KoaAuthHandler {
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function koaSession(auth: AuthRoot): KoaAuthHandler {
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function koaProviderBegin(auth: AuthRoot): KoaAuthHandler {
  return async (ctx) => {
    try {
      const id = ctx.params?.id
      if (!id) {
        await forward(executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }]), ctx)
        return
      }
      const intents = await auth.flows.beginProvider(id, (ctx.request.body ?? {}) as unknown)
      await forward(executeIntents(intents), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/**
 * Namespace merge for `KoaAdapter`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace KoaAdapter {
  /** Alias for `KoaAuthHandler`. */
  export type IHandler = KoaAuthHandler
  /** Alias for `KoaLikeContext`. */
  export type IContext = KoaLikeContext
}
