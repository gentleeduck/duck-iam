/**
 * Koa adapter. Koa is Node-native and uses ctx.req / ctx.request, so
 * the adapter translates between Web-Fetch responses (from
 * authExecuteIntents) and Koa's ctx response API.
 *
 * Mount each handler:
 *
 *   router.post('/auth/signin',  authKoaSignIn(auth))
 *   router.post('/auth/signout', authKoaSignOut(auth))
 *   router.get('/auth/session',  authKoaSession(auth))
 *   router.post('/auth/providers/:id/begin', authKoaProviderBegin(auth))
 */

import type { AuthEngine } from '../../core/auth'
import {
  authErrorToHttp,
  authExecuteIntents,
  authExtractSetCookies,
  authIsValidProviderId,
  authNodeHeadersToFetch,
  authParseProviderBeginBody,
  authParseSignInBody,
} from '../generic'

const toFetchHeaders: (headers: AuthKoaAdapter.IContext['request']['headers']) => Headers = authNodeHeadersToFetch

/**
 * Forward a Web Fetch `Response` (from authExecuteIntents) onto a Koa
 * ctx. Set-Cookie multiplicity preserved by using `append()` when the
 * Koa version supports it; falls back to `set()` with a string-array.
 */
async function forward(response: Response, ctx: AuthKoaAdapter.IContext): Promise<void> {
  ctx.status = response.status
  const cookies = authExtractSetCookies(response)
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

function handleError(err: unknown, ctx: AuthKoaAdapter.IContext): void {
  const { status, body } = authErrorToHttp(err)
  ctx.status = status
  ctx.set('content-type', 'application/json; charset=utf-8')
  ctx.body = JSON.stringify(body)
}

/** Koa handler for the sign-in route. */
export function authKoaSignIn(auth: AuthEngine): AuthKoaAdapter.IHandler {
  return async (ctx) => {
    try {
      const parsed = authParseSignInBody(ctx.request.body)
      if (!parsed) {
        return forward(authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), ctx)
      }
      const result = await auth.flows.signIn(parsed)
      await forward(authExecuteIntents(result.intents), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/** Koa handler for sign-out. */
export function authKoaSignOut(auth: AuthEngine): AuthKoaAdapter.IHandler {
  return async (ctx) => {
    try {
      const sid = auth.transport.extract({ headers: toFetchHeaders(ctx.request.headers) })
      if (!sid) {
        await forward(authExecuteIntents(auth.transport.revoke()), ctx)
        return
      }
      const { intents } = await auth.flows.signOut(sid)
      await forward(authExecuteIntents(intents), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

/** Koa handler for the session-introspection route. */
export function authKoaSession(auth: AuthEngine): AuthKoaAdapter.IHandler {
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

/** Koa handler for the per-provider begin step. */
export function authKoaProviderBegin(auth: AuthEngine): AuthKoaAdapter.IHandler {
  return async (ctx) => {
    try {
      const id = ctx.params?.id
      if (!authIsValidProviderId(id)) {
        await forward(authExecuteIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }]), ctx)
        return
      }
      const body = authParseProviderBeginBody(ctx.request.body)
      if (body === null) {
        await forward(authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }]), ctx)
        return
      }
      const intents = await auth.flows.beginProvider(id, body)
      await forward(authExecuteIntents(intents), ctx)
    } catch (err) {
      handleError(err, ctx)
    }
  }
}

export namespace AuthKoaAdapter {
  export type IHandler = (ctx: AuthKoaAdapter.IContext) => Promise<void>

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
