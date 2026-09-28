import type { AppAuth } from '@examples/duck-iam-shared/auth'
import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { signUp } from '@examples/duck-iam-shared/signup'
import { expressCsrf, mountSession, mountSignIn, mountSignOut } from '@gentleduck/auth/server/express'
import { Router } from 'express'
import { db } from '../db'

export function authRouter(auth: AppAuth, engine: AppEngine) {
  const router = Router()

  // duck-auth's own handlers guard their CSRF themselves.
  router.post('/signin', mountSignIn(auth))
  router.post('/signout', mountSignOut(auth))
  router.get('/session', mountSession(auth))

  // Everything below is this app's own, so it takes the guard.
  router.use(expressCsrf(auth))

  router.post('/signup', async (req, res) => {
    const result = await signUp(auth, db, (id, companyId) => engine.admin.assignRole(id, 'admin', companyId), req.body)
    res.status(201).json(result)
  })

  return router
}
