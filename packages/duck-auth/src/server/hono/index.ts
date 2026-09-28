import { withRequestActor } from '~/core/actor'
import type { Csrf } from '~/core/csrf'
import { csrfGuard } from '~/core/csrf'
import type { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import {
  type ActorOptions,
  type CallerFingerprint,
  callerContext,
  errorResponse,
  executeIntents,
  isValidProviderId,
  jsonResponse,
  oauthCallback,
  parseBodyStringField,
  parseProviderBeginBody,
  parseSignInBody,
  readBodyJson,
  readBodyText,
  redirectForScript,
  requestSecurity,
} from '../generic'
import type { HonoAdapter, MountHono } from './hono.types'

/** Hono exposes no resolved address, so `ctx.ip` is whatever the app chose to put there. */
export function honoCaller(ctx: { ip?: string; req: { header: (n?: string) => unknown } }): CallerFingerprint {
  const ua = ctx.req.header('user-agent')
  return callerContext({ ip: ctx.ip, userAgent: typeof ua === 'string' ? ua : undefined })
}

function reqHeaders(ctx: HonoAdapter.Context): Headers {
  return ctx.req.raw.headers
}

function reqMethod(ctx: HonoAdapter.Context): string {
  return ctx.req.raw.method
}

/** CSRF-guarded. */
export function honoSignIn(auth: AuthEngine): HonoAdapter.Handler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const parsed = parseSignInBody(await readBodyJson(ctx.req.raw))
      if (!parsed) {
        return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
      }
      const result = await auth.flows.signIn({
        ...parsed,
        ...honoCaller(ctx),
        previousSid: auth.transport.extract({ headers: reqHeaders(ctx) }) ?? undefined,
      })
      return executeIntents(result.intents)
    } catch (err) {
      return errorResponse(err)
    }
  }
}

/** CSRF-guarded. */
export function honoSignOut(auth: AuthEngine): HonoAdapter.Handler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const sid = auth.transport.extract({ headers: reqHeaders(ctx) })
      if (!sid) return executeIntents(auth.transport.revoke())
      const { intents } = await auth.flows.signOut(sid)
      return executeIntents(intents)
    } catch (err) {
      return errorResponse(err)
    }
  }
}

/** Hono handler answering the current session. */
export function honoSession(auth: AuthEngine): HonoAdapter.Handler {
  return async (ctx) => {
    try {
      const resolved = await auth.resolveSession({ headers: reqHeaders(ctx) }).orNull()
      // `csrfHash` is server-side state: the browser holds the plaintext in its cookie and never needs the hash.
      const { csrfHash: _csrfHash, ...session } = resolved?.session ?? { csrfHash: null }
      const body = resolved ? { session, identity: resolved.identity } : { session: null, identity: null }
      return jsonResponse(200, body)
    } catch (err) {
      return errorResponse(err)
    }
  }
}

/** Hono handler starting a provider flow. */
export function honoProviderBegin(auth: AuthEngine): HonoAdapter.Handler {
  return async (ctx) => {
    try {
      await csrfGuard(auth, { method: reqMethod(ctx), headers: reqHeaders(ctx) })
      const id = ctx.req.param('id')
      if (!isValidProviderId(id)) {
        return executeIntents([{ type: 'error', code: 'AUTH_PROVIDER_FAILED', status: 400 }])
      }
      const body = parseProviderBeginBody(await readBodyJson(ctx.req.raw))
      if (body === null) {
        return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
      }
      return executeIntents(redirectForScript(await auth.flows.beginProvider(id, body), reqHeaders(ctx)))
    } catch (err) {
      return errorResponse(err)
    }
  }
}

/** Convert a native Hono Context into the structural {@link HonoAdapter.Context}. */
export function toHonoAdapterCtx(c: MountHono.HonoCtx): HonoAdapter.Context {
  return {
    req: {
      header: (name?: string) => {
        if (name === undefined) {
          const out: Record<string, string> = {}
          c.req.raw.headers.forEach((v, k) => {
            out[k] = v
          })
          return out
        }
        const value = c.req.header(name)
        return typeof value === 'string' ? value : undefined
      },
      method: c.req.method,
      param: (n: string) => c.req.param(n),
      raw: c.req.raw,
      url: c.req.url,
    },
  }
}

/** Register every duck-auth route on a Hono `app`. `opts.skip` omits route groups. CORS is the app's to
 *  mount, with `hono/cors`. A body past 100 KiB is refused unread. */
export function mountHono<C extends MountHono.HonoCtx = MountHono.HonoCtx>(
  app: MountHono.App<C>,
  auth: AuthEngine,
  opts: MountHono.Options<C> = {},
): void {
  const prefix = opts.prefix ?? '/auth'
  const skip = new Set(opts.skip ?? [])

  app.post(`${prefix}/signin`, (c) => honoSignIn(auth)({ ...toHonoAdapterCtx(c), ip: opts.ip?.(c) }))
  app.post(`${prefix}/signout`, (c) => honoSignOut(auth)(toHonoAdapterCtx(c)))
  app.get(`${prefix}/session`, (c) => honoSession(auth)(toHonoAdapterCtx(c)))
  app.post(`${prefix}/providers/:id/begin`, (c) => honoProviderBegin(auth)(toHonoAdapterCtx(c)))

  if (!skip.has('oauth')) {
    const callback = async (c: C): Promise<Response> => {
      try {
        const body = c.req.method === 'POST' ? ((await readBodyText(c.req.raw)) ?? '') : undefined
        const req = { body, cookie: c.req.header('cookie'), method: c.req.method, url: c.req.url }
        return executeIntents(
          await oauthCallback(auth, c.req.param('id'), req, honoCaller({ ip: opts.ip?.(c), req: c.req })),
        )
      } catch (err) {
        return errorResponse(err)
      }
    }
    // Not CSRF-guarded, the POST included: see `oauthCallback`.
    app.get(`${prefix}/providers/:id/callback`, callback)
    app.post(`${prefix}/providers/:id/callback`, callback)
  }

  if (!skip.has('magic-link')) {
    app.get(`${prefix}/magic-link/verify`, async (c) => {
      const url = new URL(c.req.url)
      const token = url.searchParams.get('token') ?? ''
      try {
        const result = await auth.flows.signIn({
          input: { token },
          providerId: 'magic-link',
          ...honoCaller({ ip: opts.ip?.(c), req: c.req }),
          previousSid: auth.transport.extract(c.req.raw) ?? undefined,
        })
        return executeIntents(result.intents)
      } catch (err) {
        return errorResponse(err)
      }
    })
  }

  if (!skip.has('passkey')) {
    app.post(`${prefix}/passkey/begin`, async (c) => {
      try {
        // Guarded like `/signin` and `/providers/:id/begin`, which these two mirror. An unauthenticated
        // request still gets the double-submit check, against the cookie alone.
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const body = parseProviderBeginBody(await readBodyJson(c.req.raw))
        if (body === null) {
          return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
        }
        const intents = await auth.flows.beginProvider('passkey', body)
        return executeIntents(intents)
      } catch (err) {
        return errorResponse(err)
      }
    })
    app.post(`${prefix}/passkey/complete`, async (c) => {
      try {
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const body = (await readBodyJson(c.req.raw)) ?? {}
        const result = await auth.flows.signIn({
          input: body,
          providerId: 'passkey',
          ...honoCaller({ ip: opts.ip?.(c), req: c.req }),
          previousSid: auth.transport.extract(c.req.raw) ?? undefined,
        })
        return executeIntents(result.intents)
      } catch (err) {
        return errorResponse(err)
      }
    })
  }

  if (!skip.has('totp')) {
    // MFA mutators derive identityId from session (not body) and CSRF-guard.
    app.post(`${prefix}/mfa/totp/begin`, async (c) => {
      try {
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers }).orNull()
        if (!resolved?.session.identityId) {
          return executeIntents([{ type: 'error', code: 'AUTH_UNAUTHENTICATED', status: 401 }])
        }
        const raw = await readBodyJson(c.req.raw)
        const label = parseBodyStringField(raw, 'label', 128)
        if (label === null) {
          return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
        }
        // The session's own tenant, as `flows.completeStepUp` passes it. `MfaFacet` defaults `ctx` to `{}`,
        // which reads and writes unscoped: enrolling here stamped a global row, and verifying here spent a
        // factor enrolled in any other tenant.
        const tenant = resolved.session.tenantId !== null ? { tenantId: resolved.session.tenantId } : {}
        return jsonResponse(200, await auth.mfa.beginTotpEnrollment(resolved.session.identityId, label, tenant))
      } catch (err) {
        return errorResponse(err)
      }
    })
    app.post(`${prefix}/mfa/totp/confirm`, async (c) => {
      try {
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers }).orNull()
        if (!resolved?.session.identityId) {
          return executeIntents([{ type: 'error', code: 'AUTH_UNAUTHENTICATED', status: 401 }])
        }
        const raw = await readBodyJson(c.req.raw)
        const code = parseBodyStringField(raw, 'code', 64)
        if (code === null) {
          return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
        }
        const tenant = resolved.session.tenantId !== null ? { tenantId: resolved.session.tenantId } : {}
        const result = await auth.mfa.confirmTotpEnrollment(resolved.session.identityId, code, tenant)
        return jsonResponse(result.ok ? 200 : 400, result)
      } catch (err) {
        return errorResponse(err)
      }
    })
    app.post(`${prefix}/mfa/totp/verify`, async (c) => {
      try {
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers }).orNull()
        if (!resolved?.session.identityId) {
          return executeIntents([{ type: 'error', code: 'AUTH_UNAUTHENTICATED', status: 401 }])
        }
        const raw = await readBodyJson(c.req.raw)
        const code = parseBodyStringField(raw, 'code', 64)
        if (code === null) {
          return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
        }
        // SECURITY: this route answers `{ ok: false }` with a 200 however often it is asked, which is a
        // clean six-digit oracle for a caller who already has the password. The same bucket
        // `completeStepUp` uses, so grinding cannot buy a second budget by switching routes.
        const limited = await auth.limiter.consume(`stepup:${resolved.session.identityId}`)
        if (!limited.ok) await refuseRateLimited(auth.events, limited, resolved.session.identityId)
        const tenant = resolved.session.tenantId !== null ? { tenantId: resolved.session.tenantId } : {}
        return jsonResponse(200, { ok: await auth.mfa.verifyTotp(resolved.session.identityId, code, tenant) })
      } catch (err) {
        return errorResponse(err)
      }
    })
    app.post(`${prefix}/mfa/totp/remove`, async (c) => {
      try {
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers }).orNull()
        if (!resolved?.session.identityId) {
          return executeIntents([{ type: 'error', code: 'AUTH_UNAUTHENTICATED', status: 401 }])
        }
        // SECURITY: proving the factor is what may delete it. This route took any authenticated
        // session, so a caller holding only the password could delete the second factor that exists
        // for exactly that theft - cheaper than guessing a code, and it is the one mounted route that
        // destroys a credential. `AUTH_STEP_UP_REQUIRED` carries the challenge back.
        const stepUp = await auth.flows.checkStepUp(resolved.session, { aal: 2 })
        if (!stepUp.satisfied) {
          throw new AuthError('AUTH_STEP_UP_REQUIRED', { challenge: stepUp })
        }
        const tenant = resolved.session.tenantId !== null ? { tenantId: resolved.session.tenantId } : {}
        await auth.mfa.removeTotp(resolved.session.identityId, tenant)
        return jsonResponse(200, { ok: true })
      } catch (err) {
        return errorResponse(err)
      }
    })
    app.post(`${prefix}/mfa/backup-codes/regenerate`, async (c) => {
      try {
        await csrfGuard(auth, { method: c.req.raw.method, headers: c.req.raw.headers })
        const resolved = await auth.resolveSession({ headers: c.req.raw.headers }).orNull()
        if (!resolved?.session.identityId) {
          return executeIntents([{ type: 'error', code: 'AUTH_UNAUTHENTICATED', status: 401 }])
        }
        // SECURITY: proving the factor is what may replace it, as on `/mfa/totp/remove`. This answered any
        // authenticated session with ten working second factors in the body, so a caller holding only the
        // password read a set out and spent one on `completeStepUp` - AAL2 without ever holding the phone,
        // and the victim's own codes destroyed on the way through.
        const stepUp = await auth.flows.checkStepUp(resolved.session, { aal: 2 })
        if (!stepUp.satisfied) {
          throw new AuthError('AUTH_STEP_UP_REQUIRED', { challenge: stepUp })
        }
        const tenant = resolved.session.tenantId !== null ? { tenantId: resolved.session.tenantId } : {}
        return jsonResponse(200, { codes: await auth.mfa.regenerateBackupCodes(resolved.session.identityId, tenant) })
      } catch (err) {
        return errorResponse(err)
      }
    })
  }
}

/** {@link ActorOptions} over Hono's context. */
export type HonoActorOptions = ActorOptions<HonoAdapter.Context>

/** Bind the request's actor scope for everything downstream; install it above your own routes,
 *  alongside the CSRF guard. See `core/actor/README.md` for what runs unbound and what raises. */
export function honoActorContext(auth: AuthEngine, opts: HonoActorOptions = {}): HonoAdapter.Middleware {
  return async (ctx, next) => {
    try {
      await withRequestActor(
        auth,
        { headers: ctx.req.raw.headers },
        () => next(),
        requestSecurity(auth, { caller: opts.getCaller?.(ctx), onAnomaly: opts.onAnomaly, onHijack: opts.onHijack }),
      )
    } catch (err) {
      // A refusal is answered here, since Hono's default `onError` answers any throw with a 500. A
      // failure is still raised to it.
      if (err instanceof AuthError && err.status < 500) return errorResponse(err)
      throw err
    }
    return undefined
  }
}

/** CSRF guard for your own routes: `app.use('*', honoCsrf(auth))`. */
export function honoCsrf(auth: AuthEngine, opts: Csrf.GuardOptions = {}): HonoAdapter.Middleware {
  return async (ctx, next) => {
    try {
      await csrfGuard(auth, { headers: reqHeaders(ctx), method: reqMethod(ctx) }, opts)
    } catch (err) {
      return errorResponse(err)
    }
    await next()
    return undefined
  }
}

export type { HonoAdapter, MountHono } from './hono.types'
