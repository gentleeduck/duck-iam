import { type AppAuth, landing, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signUp } from '@examples/duck-auth-shared/signup'
import {
  applyIntents,
  expressCaller,
  expressCsrf,
  mountProviderBegin,
  mountSession,
  mountSignIn,
  mountSignOut,
  toHeaders,
} from '@gentleduck/auth/server/express'
import { oauthCallback } from '@gentleduck/auth/server/generic'
import express, { type RequestHandler, Router } from 'express'

export function authRouter(auth: AppAuth) {
  const router = Router()

  router.get('/providers', (_req, res) => {
    res.json({ providers: auth.providers.list() })
  })

  // duck-auth's own handlers guard their CSRF themselves.
  router.post('/signin', mountSignIn(auth))
  router.post('/signout', mountSignOut(auth))
  router.get('/session', mountSession(auth))
  router.post('/providers/:id/begin', mountProviderBegin(auth))

  // Where the IdP returns the browser; the cookies land, then the app takes over.
  const callback: RequestHandler = async (req, res) => {
    const request = { body: req.body, cookie: req.headers.cookie, method: req.method, url: req.url }
    const intents = await landing(oauthCallback(auth, req.params.id, request, expressCaller(req)))
    applyIntents(intents, res)
  }
  router.get('/providers/:id/callback', callback)
  router.post('/providers/:id/callback', express.urlencoded({ extended: false }), callback)

  // Everything below is this app's own, so it takes the guard.
  router.use(expressCsrf(auth))

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
