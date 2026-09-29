import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { beginProvider, currentSession, providerCallback, signIn, signOut } from '@examples/duck-auth-shared/routes'
import { signUp } from '@examples/duck-auth-shared/signup'
import { elysiaCaller, elysiaCsrf } from '@gentleduck/auth/server/elysia'
import { executeIntents, jsonResponse, readBodyText } from '@gentleduck/auth/server/generic'
import { Elysia } from 'elysia'
import { type WithServer, withIp } from '../ip'

export function authRoutes(auth: AppAuth) {
  // Where the IdP returns the browser. The body is left unparsed so Apple's form post reads as a query string.
  const callback = async (ctx: WithServer & { params: { id: string } }) => {
    const { request } = ctx
    const params =
      request.method === 'POST'
        ? new URLSearchParams((await readBodyText(request)) ?? '')
        : new URL(request.url).searchParams
    return executeIntents(
      await providerCallback(auth, ctx.params.id, params, request.headers, elysiaCaller(withIp(ctx))),
    )
  }

  return (
    new Elysia({ prefix: '/auth' })
      .get('/providers', () => ({ providers: auth.providers.list() }))

      .get('/providers/:id/callback', callback)
      .post('/providers/:id/callback', callback, { parse: 'none' })

      // Hooks cover only the routes after them: everything below takes the guard.
      .onBeforeHandle(elysiaCsrf(auth))

      .post('/signin', async (ctx) =>
        executeIntents(await signIn(auth, ctx.request.headers, ctx.body, elysiaCaller(withIp(ctx)))),
      )
      .post('/signout', async ({ request }) => executeIntents(await signOut(auth, request.headers)))
      .get('/session', async ({ request }) => jsonResponse(200, await currentSession(auth, request.headers)))
      .post('/providers/:id/begin', async ({ body, params }) =>
        executeIntents(await beginProvider(auth, params.id, body)),
      )

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
