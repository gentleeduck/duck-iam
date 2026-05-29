import type { AuthRoot } from '../../core/auth'
import { csrfGuard } from '../../core/csrf'
import { errorToHttp, executeIntents, parseBodyStringField, parseProviderBeginBody, parseSignInBody } from '../generic'

function reqHeaders(ctx: HonoAdapter.IContext): Headers {
  return ctx.req.raw.headers
}

function reqMethod(ctx: HonoAdapter.IContext): string {
  return ctx.req.raw.method
}

/**
 * `honoSignIn`. CSRF-guarded.
 */
export function honoSignIn(auth: AuthRoot): HonoAdapter.IHandler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const parsed = parseSignInBody(await ctx.req.json().catch(() => null))
      if (!parsed) {
        return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn(parsed)
      return executeIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * `honoSignOut`. CSRF-guarded.
 */
export function honoSignOut(auth: AuthRoot): HonoAdapter.IHandler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const sid = auth.transport.extract({ headers: reqHeaders(ctx) })
      if (!sid) return executeIntents(auth.transport.revoke())
      const { intents } = await auth.flows.signOut(sid)
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/**
 * `honoSession`.
 */
export function honoSession(auth: AuthRoot): HonoAdapter.IHandler {
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

/**
 * `honoProviderBegin`.
 */
export function honoProviderBegin(auth: AuthRoot): HonoAdapter.IHandler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const id = ctx.req.param('id')
      if (!id) {
        return executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }])
      }
      const body = parseProviderBeginBody(await ctx.req.json().catch(() => null))
      if (body === null) {
        return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
      }
      const intents = await auth.flows.beginProvider(id, body)
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

function handleError(err: unknown): Response {
  const { status, body } = errorToHttp(err)
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

/**
 * Namespace merge for HonoAdapter. Co-locates the config + input +
 * output shapes via TS namespace declaration.
 */
export namespace HonoAdapter {
  export type IHandler = (ctx: HonoAdapter.IContext) => Promise<Response>

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

/**
 * Convert a native Hono Context into the structural
 * {@link HonoAdapter.IContext} the per-handler exports above expect.
 * Exported so consumers wiring routes by hand can avoid the 30-line
 * boilerplate; {@link mountHono} folds this for the common case.
 */
export function toHonoAdapterCtx(c: {
  req: {
    method: string
    url: string
    raw: Request
    json: () => Promise<unknown>
    param: (n: string) => string | undefined
    header: (n?: string) => unknown
  }
}): HonoAdapter.IContext {
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
      }) as HonoAdapter.IContext['req']['header'],
      json: () => c.req.json(),
      method: c.req.method,
      param: (n: string) => c.req.param(n) as string | undefined,
      raw: c.req.raw,
      url: c.req.url,
    },
  }
}

/**
 * Register every duck-auth route on a Hono `app` in one call.
 *
 * Mounts the following routes (under `opts.prefix`, default `/auth`):
 *
 * ```
 * POST   /signin                   -> honoSignIn(auth)
 * POST   /signout                  -> honoSignOut(auth)
 * GET    /session                  -> honoSession(auth)
 * POST   /providers/:id/begin      -> honoProviderBegin(auth)
 * GET    /providers/:provider/callback   -> flows.signIn(provider, { code, state })
 * GET    /magic-link/verify        -> flows.signIn('magic-link', { token })
 * POST   /passkey/begin            -> flows.beginProvider('passkey', body)
 * POST   /passkey/complete         -> flows.signIn('passkey', body)
 * POST   /mfa/totp/begin           -> mfa.beginTotpEnrollment
 * POST   /mfa/totp/confirm         -> mfa.confirmTotpEnrollment
 * POST   /mfa/totp/verify          -> mfa.verifyTotp
 * POST   /mfa/totp/remove          -> mfa.removeTotp
 * POST   /mfa/backup-codes/regenerate
 * ```
 *
 * `opts.skip` (`['passkey'] | ['totp'] | ['oauth'] | ['magic-link']`)
 * omits the routes in that group when the consumer doesn't expose
 * those flows publicly. `opts.cors` flips on a permissive CORS
 * middleware scoped to the auth routes only.
 *
 * Pass a duck-typed `app` (`{ get, post }`) so we avoid pulling Hono
 * into the auth lib's type graph (Hono stays a peer dep).
 *
 * @example
 * ```ts
 * import { Hono } from 'hono'
 * import { mountHono } from '@gentleduck/auth/server/hono'
 * import { auth } from './auth'
 *
 * const app = new Hono()
 * mountHono(app, auth)
 *
 * // Or with overrides:
 * mountHono(app, auth, { prefix: '/api/auth', skip: ['passkey'] })
 * ```
 */
export function mountHono(app: MountHono.IApp, auth: AuthRoot, opts: MountHono.IOptions = {}): void {
  const prefix = opts.prefix ?? '/auth'
  const skip = new Set(opts.skip ?? [])

  // Core routes are always on.
  app.post(`${prefix}/signin`, (c) => honoSignIn(auth)(toHonoAdapterCtx(c)))
  app.post(`${prefix}/signout`, (c) => honoSignOut(auth)(toHonoAdapterCtx(c)))
  app.get(`${prefix}/session`, (c) => honoSession(auth)(toHonoAdapterCtx(c)))
  app.post(`${prefix}/providers/:id/begin`, (c) => honoProviderBegin(auth)(toHonoAdapterCtx(c)))

  if (!skip.has('oauth')) {
    app.get(`${prefix}/providers/:provider/callback`, async (c) => {
      // `as string` cast hid the fact that c.req.param can return
      // undefined when the URL doesn't match. Validate explicitly.
      const provider = c.req.param('provider')
      if (typeof provider !== 'string' || provider.length === 0) {
        return executeIntents([{ type: 'error', code: 'AUTH/PROVIDER_FAILED', status: 400 }])
      }
      const url = new URL(c.req.url)
      const code = url.searchParams.get('code') ?? ''
      const state = url.searchParams.get('state') ?? ''
      try {
        const result = await auth.flows.signIn({ input: { code, state }, providerId: provider })
        return executeIntents(result.intents)
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
        return executeIntents(result.intents)
      } catch (err) {
        return handleError(err)
      }
    })
  }

  if (!skip.has('passkey')) {
    app.post(`${prefix}/passkey/begin`, async (c) => {
      try {
        const body = parseProviderBeginBody(await c.req.json().catch(() => null))
        if (body === null) {
          return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
        }
        const intents = await auth.flows.beginProvider('passkey', body)
        return executeIntents(intents)
      } catch (err) {
        return handleError(err)
      }
    })
    app.post(`${prefix}/passkey/complete`, async (c) => {
      try {
        // body is provider-specific input - passkey provider validates
        // shape internally. The legacy `as unknown` cast was cosmetic.
        const body: unknown = await c.req.json().catch(() => ({}))
        const result = await auth.flows.signIn({ input: body, providerId: 'passkey' })
        return executeIntents(result.intents)
      } catch (err) {
        return handleError(err)
      }
    })
  }

  if (!skip.has('totp')) {
    // MFA mutators derive identityId from session (not body) and CSRF-guard.
    app.post(`${prefix}/mfa/totp/begin`, async (c) => {
      try {
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers })
        if (!resolved?.session.identityId) {
          return executeIntents([{ type: 'error', code: 'AUTH/UNAUTHENTICATED', status: 401 }])
        }
        const raw = await c.req.json().catch(() => null)
        const label = parseBodyStringField(raw, 'label', 128)
        if (label === null) {
          return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
        }
        return jsonResponse(200, await auth.mfa.beginTotpEnrollment(resolved.session.identityId, label))
      } catch (err) {
        return handleError(err)
      }
    })
    app.post(`${prefix}/mfa/totp/confirm`, async (c) => {
      try {
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers })
        if (!resolved?.session.identityId) {
          return executeIntents([{ type: 'error', code: 'AUTH/UNAUTHENTICATED', status: 401 }])
        }
        const raw = await c.req.json().catch(() => null)
        const code = parseBodyStringField(raw, 'code', 64)
        if (code === null) {
          return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
        }
        const result = await auth.mfa.confirmTotpEnrollment(resolved.session.identityId, code)
        return jsonResponse(result.ok ? 200 : 400, result)
      } catch (err) {
        return handleError(err)
      }
    })
    app.post(`${prefix}/mfa/totp/verify`, async (c) => {
      try {
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers })
        if (!resolved?.session.identityId) {
          return executeIntents([{ type: 'error', code: 'AUTH/UNAUTHENTICATED', status: 401 }])
        }
        const raw = await c.req.json().catch(() => null)
        const code = parseBodyStringField(raw, 'code', 64)
        if (code === null) {
          return executeIntents([{ type: 'error', code: 'AUTH/INVALID_CREDENTIALS', status: 400 }])
        }
        return jsonResponse(200, { ok: await auth.mfa.verifyTotp(resolved.session.identityId, code) })
      } catch (err) {
        return handleError(err)
      }
    })
    app.post(`${prefix}/mfa/totp/remove`, async (c) => {
      try {
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers })
        if (!resolved?.session.identityId) {
          return executeIntents([{ type: 'error', code: 'AUTH/UNAUTHENTICATED', status: 401 }])
        }
        await auth.mfa.removeTotp(resolved.session.identityId)
        return jsonResponse(200, { ok: true })
      } catch (err) {
        return handleError(err)
      }
    })
    app.post(`${prefix}/mfa/backup-codes/regenerate`, async (c) => {
      try {
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers })
        if (!resolved?.session.identityId) {
          return executeIntents([{ type: 'error', code: 'AUTH/UNAUTHENTICATED', status: 401 }])
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

/**
 * Namespace merge for {@link mountHono}.
 */
export namespace MountHono {
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
