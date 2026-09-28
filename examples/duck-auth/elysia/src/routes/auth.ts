import { type AppAuth, landing, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signUp } from '@examples/duck-auth-shared/signup'
import {
  elysiaCaller,
  elysiaCsrf,
  elysiaProviderBegin,
  elysiaSession,
  elysiaSignIn,
  elysiaSignOut,
} from '@gentleduck/auth/server/elysia'
import { executeIntents, oauthCallback } from '@gentleduck/auth/server/generic'
import { Elysia } from 'elysia'
import { type WithServer, withIp } from '../ip'

export function authRoutes(auth: AppAuth) {
  // Where the IdP returns the browser; the cookies land, then the app takes over.
  const callback = async (ctx: WithServer & { params: { id: string } }) => {
    const { request, body, params } = ctx
    const req = { body, cookie: request.headers.get('cookie'), method: request.method, url: request.url }
    const intents = await landing(oauthCallback(auth, params.id, req, elysiaCaller(withIp(ctx))))
    return executeIntents(intents)
  }

  return (
    new Elysia({ prefix: '/auth' })
      .get('/providers', () => ({ providers: auth.providers.list() }))

      // duck-auth's own handlers guard their CSRF themselves.
      .post('/signin', (ctx) => elysiaSignIn(auth)(withIp(ctx)))
      .post('/signout', (ctx) => elysiaSignOut(auth)(withIp(ctx)))
      .get('/session', (ctx) => elysiaSession(auth)(withIp(ctx)))
      .post('/providers/:id/begin', (ctx) => elysiaProviderBegin(auth)(withIp(ctx)))

      .get('/providers/:id/callback', callback)
      .post('/providers/:id/callback', callback)

      // Hooks cover only the routes after them: everything below is this app's own, so it takes the guard.
      .onBeforeHandle(elysiaCsrf(auth))

      .post('/signup', async ({ body, set }) => {
        set.status = 201
        return signUp(auth, body)
      })

      .post('/password/forgot', async ({ body }) => {
        await auth.flows.requestPasswordReset({
          input: { email: readString(body, 'email') ?? '', callbackPath: PAGES.resetPassword },
          findIdentityByEmail: (e) => auth.identities.getByEmail(e).orNull(),
        })
        return { ok: true }
      })

      .post('/password/reset', async ({ body, request }) => {
        const { intents } = await auth.flows.completePasswordReset({
          token: readString(body, 'token') ?? '',
          newPassword: readString(body, 'password') ?? '',
          currentSid: auth.transport.extract({ headers: request.headers }) ?? undefined,
        })
        return executeIntents([...intents, { type: 'json', status: 200, body: { ok: true } }])
      })

      .post('/email/verify', async ({ body }) => {
        const { identityId } = await auth.flows.completeEmailVerification({ token: readString(body, 'token') ?? '' })
        return { identityId }
      })
  )
}
