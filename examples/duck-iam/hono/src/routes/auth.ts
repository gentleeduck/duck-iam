import type { AppAuth } from '@examples/duck-iam-shared/auth'
import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { currentSession, signIn, signOut } from '@examples/duck-iam-shared/routes'
import { signUp } from '@examples/duck-iam-shared/signup'
import { executeIntents, jsonResponse, readBodyJson } from '@gentleduck/auth/server/generic'
import { honoCaller, honoCsrf, toHonoAdapterCtx } from '@gentleduck/auth/server/hono'
import { type Context, Hono } from 'hono'
import { getConnInfo } from 'hono/bun'
import { db } from '../db'

/** Hono resolves no caller address itself; Bun's socket has it. */
const withIp = (c: Context) => ({ ...toHonoAdapterCtx(c), ip: getConnInfo(c).remote.address })

export function authRouter(auth: AppAuth, engine: AppEngine) {
  const router = new Hono()

  router.use((c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))

  router.post('/signin', async (c) => {
    const body = await readBodyJson(c.req.raw)
    return executeIntents(await signIn(auth, c.req.raw.headers, body, honoCaller(withIp(c))))
  })

  router.post('/signout', async (c) => executeIntents(await signOut(auth, c.req.raw.headers)))

  router.get('/session', async (c) => jsonResponse(200, await currentSession(auth, c.req.raw.headers)))

  router.post('/signup', async (c) => {
    const body = await readBodyJson(c.req.raw)
    const result = await signUp(auth, db, (id, companyId) => engine.admin.assignRole(id, 'admin', companyId), body)
    return c.json(result, 201)
  })

  return router
}
