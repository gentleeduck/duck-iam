import type { AppAuth } from '@examples/duck-iam-shared/auth'
import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { signUp } from '@examples/duck-iam-shared/signup'
import { readBodyJson } from '@gentleduck/auth/server/generic'
import { honoCsrf, honoSession, honoSignIn, honoSignOut, toHonoAdapterCtx } from '@gentleduck/auth/server/hono'
import { type Context, Hono } from 'hono'
import { getConnInfo } from 'hono/bun'
import { db } from '../db'

/** Hono resolves no caller address itself; Bun's socket has it. */
const withIp = (c: Context) => ({ ...toHonoAdapterCtx(c), ip: getConnInfo(c).remote.address })

export function authRouter(auth: AppAuth, engine: AppEngine) {
  const router = new Hono()

  // duck-auth's own handlers guard their CSRF themselves.
  router.post('/signin', (c) => honoSignIn(auth)(withIp(c)))
  router.post('/signout', (c) => honoSignOut(auth)(withIp(c)))
  router.get('/session', (c) => honoSession(auth)(withIp(c)))

  // Everything below is this app's own, so it takes the guard.
  router.use((c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))

  router.post('/signup', async (c) => {
    const body = await readBodyJson(c.req.raw)
    const result = await signUp(auth, db, (id, companyId) => engine.admin.assignRole(id, 'admin', companyId), body)
    return c.json(result, 201)
  })

  return router
}
