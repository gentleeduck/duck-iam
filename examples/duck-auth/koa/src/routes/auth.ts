import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { beginProvider, currentSession, providerCallback, signIn, signOut } from '@examples/duck-auth-shared/routes'
import { signUp } from '@examples/duck-auth-shared/signup'
import { nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import { koaApplyIntents, koaCaller, koaCsrf } from '@gentleduck/auth/server/koa'
import Router from '@koa/router'
import type { Context } from 'koa'

export function authRouter(auth: AppAuth) {
  const router = new Router({ prefix: '/auth' })

  router.get('/providers', (ctx) => {
    ctx.body = { providers: auth.providers.list() }
  })

  // Where the IdP returns the browser. Apple's form post is parsed as text, the same query string a redirect carries.
  const callback = async (ctx: Context & { params: Record<string, string> }) => {
    const { body, headers, method, querystring } = ctx.request
    const params = new URLSearchParams(method === 'POST' ? (typeof body === 'string' ? body : '') : querystring)
    const id = ctx.params.id ?? ''
    await koaApplyIntents(await providerCallback(auth, id, params, nodeHeadersToFetch(headers), koaCaller(ctx)), ctx)
  }
  router.get('/providers/:id/callback', callback)
  router.post('/providers/:id/callback', callback)

  // Everything below takes the guard.
  router.use(koaCsrf(auth))

  router.post('/signin', async (ctx) => {
    const { body, headers } = ctx.request
    await koaApplyIntents(await signIn(auth, nodeHeadersToFetch(headers), body, koaCaller(ctx)), ctx)
  })

  router.post('/signout', async (ctx) => {
    await koaApplyIntents(await signOut(auth, nodeHeadersToFetch(ctx.request.headers)), ctx)
  })

  router.get('/session', async (ctx) => {
    const body = await currentSession(auth, nodeHeadersToFetch(ctx.request.headers))
    await koaApplyIntents([{ type: 'json', status: 200, body }], ctx)
  })

  router.post('/providers/:id/begin', async (ctx) => {
    await koaApplyIntents(await beginProvider(auth, ctx.params.id ?? '', ctx.request.body), ctx)
  })

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
