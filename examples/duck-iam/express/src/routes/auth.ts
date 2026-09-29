import type { AppAuth } from '@examples/duck-iam-shared/auth'
import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { currentSession, signIn, signOut } from '@examples/duck-iam-shared/routes'
import { signUp } from '@examples/duck-iam-shared/signup'
import { applyIntents, expressCaller, expressCsrf, toHeaders } from '@gentleduck/auth/server/express'
import { Router } from 'express'
import { db } from '../db'

export function authRouter(auth: AppAuth, engine: AppEngine) {
  const router = Router()

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

  router.post('/signup', async (req, res) => {
    const result = await signUp(auth, db, (id, companyId) => engine.admin.assignRole(id, 'admin', companyId), req.body)
    res.status(201).json(result)
  })

  return router
}
