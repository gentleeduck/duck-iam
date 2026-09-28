import { ANONYMOUS_SUBJECT_ID, type AppEngine, access } from '@examples/duck-iam-shared/iam'
import { Hono } from 'hono'
import type { AppEnv } from '../session'
import { sessionOf } from '../session'

// One engine.permissions() call over the full action x resource matrix, so this can't drift
// from what the route guards actually enforce.
export function permissionsRouter(engine: AppEngine) {
  const router = new Hono<AppEnv>()

  router.get('/me/permissions', async (c) => {
    const session = sessionOf(c) ?? { id: ANONYMOUS_SUBJECT_ID, companyId: null }
    const scope = session.companyId ?? undefined
    const checks = access.resources.flatMap((resource) => access.actions.map((action) => ({ action, resource, scope })))
    const map = await engine.permissions(session.id, checks)
    return c.json({ subject: session.id, scope: scope ?? null, permissions: map })
  })

  return router
}
