import type { AuthEngine } from '../../core/auth'
import { authCsrfGuard } from '../../core/csrf'
import {
  authErrorToHttp,
  authExecuteIntents,
  authIsValidProviderId,
  authParseBodyStringField,
  authParseProviderBeginBody,
  authParseSignInBody,
} from '../generic'

function reqHeaders(ctx: AuthHonoAdapter.IContext): Headers {
  return ctx.req.raw.headers
}

function reqMethod(ctx: AuthHonoAdapter.IContext): string {
  return ctx.req.raw.method
}

/** `authHonoSignIn`. CSRF-guarded. */
export function authHonoSignIn(auth: AuthEngine): AuthHonoAdapter.IHandler {
  return async (ctx) => {
    try {
      await authCsrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const parsed = authParseSignInBody(await ctx.req.json().catch(() => null))
      if (!parsed) {
        return authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn(parsed)
      return authExecuteIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** `authHonoSignOut`. CSRF-guarded. */
export function authHonoSignOut(auth: AuthEngine): AuthHonoAdapter.IHandler {
  return async (ctx) => {
    try {
      await authCsrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const sid = auth.transport.extract({ headers: reqHeaders(ctx) })
      if (!sid) return authExecuteIntents(auth.transport.revoke())
      const { intents } = await auth.flows.signOut(sid)
      return authExecuteIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** `authHonoSession`. */
export function authHonoSession(auth: AuthEngine): AuthHonoAdapter.IHandler {
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

/** `authHonoProviderBegin`. */
export function authHonoProviderBegin(auth: AuthEngine): AuthHonoAdapter.IHandler {
  return async (ctx) => {
    try {
      await authCsrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const id = ctx.req.param('id')
      if (!authIsValidProviderId(id)) {
        return authExecuteIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }])
      }
      const body = authParseProviderBeginBody(await ctx.req.json().catch(() => null))
      if (body === null) {
        return authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const intents = await auth.flows.beginProvider(id, body)
      return authExecuteIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

function handleError(err: unknown): Response {
  const { status, body } = authErrorToHttp(err)
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

export namespace AuthHonoAdapter {
  export type IHandler = (ctx: AuthHonoAdapter.IContext) => Promise<Response>

  export interface IContext {
    req: {
      method: string
      url: string
      header(name?: string): string | undefined | Record<string, string>
      raw: Request
      json: () => Promise<unknown>
      param(name: string): string | undefined
    }
  }
}

/** Convert a native Hono Context into the structural {@link AuthHonoAdapter.IContext}. */
export function authToHonoAdapterCtx(c: {
  req: {
    method: string
    url: string
    raw: Request
    json: () => Promise<unknown>
    param: (n: string) => string | undefined
    header: (n?: string) => unknown
  }
}): AuthHonoAdapter.IContext {
  return {
    req: {
      header: ((name?: string) => {
        if (name === undefined) {
          const out: Record<string, string> = {}
          c.req.raw.headers.forEach((v, k) => {
            out[k] = v
          })
          return out
        }
        return c.req.header(name) as string | undefined
      }) as AuthHonoAdapter.IContext['req']['header'],
      json: () => c.req.json(),
      method: c.req.method,
      param: (n: string) => c.req.param(n) as string | undefined,
      raw: c.req.raw,
      url: c.req.url,
    },
  }
}

/** Register every duck-auth route on a Hono `app`. `opts.skip` omits route groups; `opts.cors` mounts a scoped CORS middleware. */
export function authMountHono(app: AuthMountHono.IApp, auth: AuthEngine, opts: AuthMountHono.IOptions = {}): void {
  const prefix = opts.prefix ?? '/auth'
  const skip = new Set(opts.skip ?? [])

  app.post(`${prefix}/signin`, (c) => authHonoSignIn(auth)(authToHonoAdapterCtx(c)))
  app.post(`${prefix}/signout`, (c) => authHonoSignOut(auth)(authToHonoAdapterCtx(c)))
  app.get(`${prefix}/session`, (c) => authHonoSession(auth)(authToHonoAdapterCtx(c)))
  app.post(`${prefix}/providers/:id/begin`, (c) => authHonoProviderBegin(auth)(authToHonoAdapterCtx(c)))

  if (!skip.has('oauth')) {
    app.get(`${prefix}/providers/:provider/callback`, async (c) => {
      const provider = c.req.param('provider')
      if (typeof provider !== 'string' || provider.length === 0) {
        return authExecuteIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }])
      }
      const url = new URL(c.req.url)
      const code = url.searchParams.get('code') ?? ''
      const state = url.searchParams.get('state') ?? ''
      try {
        const result = await auth.flows.signIn({ input: { code, state }, providerId: provider })
        return authExecuteIntents(result.intents)
      } catch (err) {
        return handleError(err)
      }
    })
  }

  if (!skip.has('magic-link')) {
    app.get(`${prefix}/magic-link/verify`, async (c) => {
      const url = new URL(c.req.url)
      const token = url.searchParams.get('token') ?? ''
      try {
        const result = await auth.flows.signIn({ input: { token }, providerId: 'magic-link' })
        return authExecuteIntents(result.intents)
      } catch (err) {
        return handleError(err)
      }
    })
  }

  if (!skip.has('passkey')) {
    app.post(`${prefix}/passkey/begin`, async (c) => {
      try {
        const body = authParseProviderBeginBody(await c.req.json().catch(() => null))
        if (body === null) {
          return authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
        }
        const intents = await auth.flows.beginProvider('passkey', body)
        return authExecuteIntents(intents)
      } catch (err) {
        return handleError(err)
      }
    })
    app.post(`${prefix}/passkey/complete`, async (c) => {
      try {
        const body: unknown = await c.req.json().catch(() => ({}))
        const result = await auth.flows.signIn({ input: body, providerId: 'passkey' })
        return authExecuteIntents(result.intents)
      } catch (err) {
        return handleError(err)
      }
    })
  }

  if (!skip.has('totp')) {
    // MFA mutators derive identityId from session (not body) and CSRF-guard.
    app.post(`${prefix}/mfa/totp/begin`, async (c) => {
      try {
        await authCsrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers })
        if (!resolved?.session.identityId) {
          return authExecuteIntents([{ type: 'error', code: 'AUTH/UNAUTHENTICATED', status: 401 }])
        }
        const raw = await c.req.json().catch(() => null)
        const label = authParseBodyStringField(raw, 'label', 128)
        if (label === null) {
          return authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
        }
        return jsonResponse(200, await auth.mfa.beginTotpEnrollment(resolved.session.identityId, label))
      } catch (err) {
        return handleError(err)
      }
    })
    app.post(`${prefix}/mfa/totp/confirm`, async (c) => {
      try {
        await authCsrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers })
        if (!resolved?.session.identityId) {
          return authExecuteIntents([{ type: 'error', code: 'AUTH/UNAUTHENTICATED', status: 401 }])
        }
        const raw = await c.req.json().catch(() => null)
        const code = authParseBodyStringField(raw, 'code', 64)
        if (code === null) {
          return authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
        }
        const result = await auth.mfa.confirmTotpEnrollment(resolved.session.identityId, code)
        return jsonResponse(result.ok ? 200 : 400, result)
      } catch (err) {
        return handleError(err)
      }
    })
    app.post(`${prefix}/mfa/totp/verify`, async (c) => {
      try {
        await authCsrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers })
        if (!resolved?.session.identityId) {
          return authExecuteIntents([{ type: 'error', code: 'AUTH/UNAUTHENTICATED', status: 401 }])
        }
        const raw = await c.req.json().catch(() => null)
        const code = authParseBodyStringField(raw, 'code', 64)
        if (code === null) {
          return authExecuteIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
        }
        return jsonResponse(200, { ok: await auth.mfa.verifyTotp(resolved.session.identityId, code) })
      } catch (err) {
        return handleError(err)
      }
    })
    app.post(`${prefix}/mfa/totp/remove`, async (c) => {
      try {
        await authCsrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers })
        if (!resolved?.session.identityId) {
          return authExecuteIntents([{ type: 'error', code: 'AUTH/UNAUTHENTICATED', status: 401 }])
        }
        await auth.mfa.removeTotp(resolved.session.identityId)
        return jsonResponse(200, { ok: true })
      } catch (err) {
        return handleError(err)
      }
    })
    app.post(`${prefix}/mfa/backup-codes/regenerate`, async (c) => {
      try {
        await authCsrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers })
        if (!resolved?.session.identityId) {
          return authExecuteIntents([{ type: 'error', code: 'AUTH/UNAUTHENTICATED', status: 401 }])
        }
        return jsonResponse(200, { codes: await auth.mfa.regenerateBackupCodes(resolved.session.identityId) })
      } catch (err) {
        return handleError(err)
      }
    })
  }
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    headers: { 'content-type': 'application/json; charset=utf-8' },
    status,
  })
}

export namespace AuthMountHono {
  /** Subset of Hono's `Context` we use in handlers. */
  export interface IHonoCtx {
    req: {
      method: string
      url: string
      raw: Request
      json: () => Promise<unknown>
      param: (n: string) => string | undefined
      header: (n?: string) => unknown
    }
  }
  /** Duck-typed Hono `app` - only `get` / `post` are required. Keeps Hono a peerDep. */
  export interface IApp {
    get(path: string, handler: (c: IHonoCtx) => Response | Promise<Response>): void
    post(path: string, handler: (c: IHonoCtx) => Response | Promise<Response>): void
  }

  /** Group identifiers that `opts.skip` understands. */
  export type ISkipGroup = 'oauth' | 'magic-link' | 'passkey' | 'totp'

  export interface IOptions {
    /** Default `'/auth'`. Set to `'/api/auth'` to re-root. */
    prefix?: string
    /** Skip route groups your app doesn't expose. */
    skip?: ISkipGroup[]
    /** Reserved for the upcoming `cors: true` shortcut; CORS today is set on the app directly via `hono/cors`. */
    cors?: boolean | { origins: string[] }
  }
}
