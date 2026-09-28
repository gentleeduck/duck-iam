import { type AppAuth, landing, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signUp } from '@examples/duck-auth-shared/signup'
import { nodeHeadersToFetch, oauthCallback } from '@gentleduck/auth/server/generic'
import {
  koaApplyIntents,
  koaCaller,
  koaCsrf,
  koaProviderBegin,
  koaSession,
  koaSignIn,
  koaSignOut,
} from '@gentleduck/auth/server/koa'
import Router from '@koa/router'
import type { Context } from 'koa'

export function authRouter(auth: AppAuth) {
  const router = new Router({ prefix: '/auth' })

  router.get('/providers', (ctx) => {
    ctx.body = { providers: auth.providers.list() }
  })

  // duck-auth's own handlers guard their CSRF themselves.
  router.post('/signin', koaSignIn(auth))
  router.post('/signout', koaSignOut(auth))
  router.get('/session', koaSession(auth))
  router.post('/providers/:id/begin', koaProviderBegin(auth))

  // Where the IdP returns the browser; the cookies land, then the app takes over.
  const callback = async (ctx: Context & { params: Record<string, string> }) => {
    const { body, headers, method, url } = ctx.request
    const intents = await landing(
      oauthCallback(auth, ctx.params.id, { body, cookie: headers.cookie, method, url }, koaCaller(ctx)),
    )
    await koaApplyIntents(intents, ctx)
  }
  router.get('/providers/:id/callback', callback)
  router.post('/providers/:id/callback', callback)

  // Everything below is this app's own, so it takes the guard.
  router.use(koaCsrf(auth))

  router.post('/signup', async (ctx) => {
    ctx.body = await signUp(auth, ctx.request.body)
    ctx.status = 201
  })

  router.post('/password/forgot', async (ctx) => {
    await auth.flows.requestPasswordReset({
      input: { email: readString(ctx.request.body, 'email') ?? '', callbackPath: PAGES.resetPassword },
      findIdentityByEmail: (e) => auth.identities.getByEmail(e).orNull(),
    })
    ctx.body = { ok: true }
  })

  router.post('/password/reset', async (ctx) => {
    const { body, headers } = ctx.request
    const { intents } = await auth.flows.completePasswordReset({
      token: readString(body, 'token') ?? '',
      newPassword: readString(body, 'password') ?? '',
      currentSid: auth.transport.extract({ headers: nodeHeadersToFetch(headers) }) ?? undefined,
    })
    await koaApplyIntents([...intents, { type: 'json', status: 200, body: { ok: true } }], ctx)
  })

  router.post('/email/verify', async (ctx) => {
    const token = readString(ctx.request.body, 'token') ?? ''
    const { identityId } = await auth.flows.completeEmailVerification({ token })
    ctx.body = { identityId }
  })

  return router
}
