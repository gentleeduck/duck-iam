import { authCsrfGuard } from '../../core/csrf'
import type { AuthEngine } from '../../core/engine'
import {
  errorToHttp,
  executeIntents,
  isValidProviderId,
  parseBodyStringField,
  parseProviderBeginBody,
  parseSignInBody,
} from '../generic'

import type { HonoAdapter, MountHono } from './hono.types'

function reqHeaders(ctx: HonoAdapter.Context): Headers {
  return ctx.req.raw.headers
}

function reqMethod(ctx: HonoAdapter.Context): string {
  return ctx.req.raw.method
}

/** `honoSignIn`. CSRF-guarded. */
export function honoSignIn(auth: AuthEngine): HonoAdapter.Handler {
  return async (ctx) => {
    try {
      await authCsrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const parsed = parseSignInBody(await ctx.req.json().catch(() => null))
      if (!parsed) {
        return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn(parsed)
      return executeIntents(result.intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** `honoSignOut`. CSRF-guarded. */
export function honoSignOut(auth: AuthEngine): HonoAdapter.Handler {
  return async (ctx) => {
    try {
      await authCsrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const sid = auth.transport.extract({ headers: reqHeaders(ctx) })
      if (!sid) return executeIntents(auth.transport.revoke())
      const { intents } = await auth.flows.signOut(sid)
      return executeIntents(intents)
    } catch (err) {
      return handleError(err)
    }
  }
}

/** `honoSession`. */
export function honoSession(auth: AuthEngine): HonoAdapter.Handler {
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

/** `honoProviderBegin`. */
export function honoProviderBegin(auth: AuthEngine): HonoAdapter.Handler {
  return async (ctx) => {
    try {
      await authCsrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const id = ctx.req.param('id')
      if (!isValidProviderId(id)) {
        return executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }])
      }
      const body = parseProviderBeginBody(await ctx.req.json().catch(() => null))
      if (body === null) {
        return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
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

/** Convert a native Hono Context into the structural {@link HonoAdapter.Context}. */
export function toHonoAdapterCtx(c: {
  req: {
    method: string
    url: string
    raw: Request
    json: () => Promise<unknown>
    param: (n: string) => string | undefined
    header: (n?: string) => unknown
  }
}): HonoAdapter.Context {
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
      }) as HonoAdapter.Context['req']['header'],
      json: () => c.req.json(),
      method: c.req.method,
      param: (n: string) => c.req.param(n) as string | undefined,
      raw: c.req.raw,
      url: c.req.url,
    },
  }
}

/** Register every duck-auth route on a Hono `app`. `opts.skip` omits route groups; `opts.cors` mounts a scoped CORS middleware. */
export function mountHono(app: MountHono.App, auth: AuthEngine, opts: MountHono.Options = {}): void {
  const prefix = opts.prefix ?? '/auth'
  const skip = new Set(opts.skip ?? [])

  app.post(`${prefix}/signin`, (c) => honoSignIn(auth)(toHonoAdapterCtx(c)))
  app.post(`${prefix}/signout`, (c) => honoSignOut(auth)(toHonoAdapterCtx(c)))
  app.get(`${prefix}/session`, (c) => honoSession(auth)(toHonoAdapterCtx(c)))
  app.post(`${prefix}/providers/:id/begin`, (c) => honoProviderBegin(auth)(toHonoAdapterCtx(c)))

  if (!skip.has('oauth')) {
    app.get(`${prefix}/providers/:provider/callback`, async (c) => {
      const provider = c.req.param('provider')
      if (typeof provider !== 'string' || provider.length === 0) {
        return executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }])
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
          return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
        }
        const intents = await auth.flows.beginProvider('passkey', body)
        return executeIntents(intents)
      } catch (err) {
        return handleError(err)
      }
    })
    app.post(`${prefix}/passkey/complete`, async (c) => {
      try {
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
        await authCsrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers })
        if (!resolved?.session.identityId) {
          return executeIntents([{ type: 'error', code: 'AUTH_UNAUTHENTICATED', status: 401 }])
        }
        const raw = await c.req.json().catch(() => null)
        const label = parseBodyStringField(raw, 'label', 128)
        if (label === null) {
          return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
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
          return executeIntents([{ type: 'error', code: 'AUTH_UNAUTHENTICATED', status: 401 }])
        }
        const raw = await c.req.json().catch(() => null)
        const code = parseBodyStringField(raw, 'code', 64)
        if (code === null) {
          return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
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
          return executeIntents([{ type: 'error', code: 'AUTH_UNAUTHENTICATED', status: 401 }])
        }
        const raw = await c.req.json().catch(() => null)
        const code = parseBodyStringField(raw, 'code', 64)
        if (code === null) {
          return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
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
          return executeIntents([{ type: 'error', code: 'AUTH_UNAUTHENTICATED', status: 401 }])
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
          return executeIntents([{ type: 'error', code: 'AUTH_UNAUTHENTICATED', status: 401 }])
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

export type { HonoAdapter, MountHono } from './hono.types'
