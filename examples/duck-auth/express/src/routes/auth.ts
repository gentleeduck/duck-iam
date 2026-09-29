import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { beginProvider, currentSession, providerCallback, signIn, signOut } from '@examples/duck-auth-shared/routes'
import { signUp } from '@examples/duck-auth-shared/signup'
import { applyIntents, expressCaller, expressCsrf, toHeaders } from '@gentleduck/auth/server/express'
import express, { type RequestHandler, Router } from 'express'

export function authRouter(auth: AppAuth) {
  const router = Router()

  router.get('/providers', (_req, res) => {
    res.json({ providers: auth.providers.list() })
  })

  // Where the IdP returns the browser. Apple's form post is read as text, the same query string a redirect carries.
  const callback: RequestHandler<{ id: string }> = async (req, res) => {
    const form = typeof req.body === 'string' ? req.body : ''
    const params =
      req.method === 'POST' ? new URLSearchParams(form) : new URL(req.originalUrl, 'http://localhost').searchParams
    applyIntents(await providerCallback(auth, req.params.id, params, toHeaders(req.headers), expressCaller(req)), res)
  }
  router.get('/providers/:id/callback', callback)
  router.post('/providers/:id/callback', express.text({ type: 'application/x-www-form-urlencoded' }), callback)

  // Everything below takes the guard.
  router.use(expressCsrf(auth))

  router.post('/signin', async (req, res) => {
    applyIntents(await signIn(auth, toHeaders(req.headers), req.body, expressCaller(req)), res)
  })

  router.post('/signout', async (req, res) => {
    applyIntents(await signOut(auth, toHeaders(req.headers)), res)
  })

  router.get('/session', async (req, res) => {
    applyIntents([{ type: 'json', status: 200, body: await currentSession(auth, toHeaders(req.headers)) }], res)
  })

  router.post('/providers/:id/begin', async (req, res) => {
    applyIntents(await beginProvider(auth, req.params.id, req.body), res)
  })

  router.post('/signup', async (req, res) => {
    res.status(201).json(await signUp(auth, req.body))
  })

  router.post('/password/forgot', async (req, res) => {
    const email = readString(req.body, 'email') ?? ''
    await auth.flows.requestPasswordReset({
      input: { email, callbackPath: PAGES.resetPassword },
      findIdentityByEmail: (e) => auth.identities.getByEmail(e).orNull(),
    })
    res.json({ ok: true })
  })

  router.post('/password/reset', async (req, res) => {
    const { intents } = await auth.flows.completePasswordReset({
      token: readString(req.body, 'token') ?? '',
      newPassword: readString(req.body, 'password') ?? '',
      currentSid: auth.transport.extract({ headers: toHeaders(req.headers) }) ?? undefined,
    })
    applyIntents([...intents, { type: 'json', status: 200, body: { ok: true } }], res)
  })

  router.post('/email/verify', async (req, res) => {
    const { identityId } = await auth.flows.completeEmailVerification({ token: readString(req.body, 'token') ?? '' })
    res.json({ identityId })
  })

  return router
}
