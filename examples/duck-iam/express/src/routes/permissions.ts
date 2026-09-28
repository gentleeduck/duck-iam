import { ANONYMOUS_SUBJECT_ID, type AppEngine, access } from '@examples/duck-iam-shared/iam'
import { Router } from 'express'

// One engine.permissions() call over the full action x resource matrix, so this can't drift
// from what the route guards actually enforce.
export function permissionsRouter(engine: AppEngine) {
  const router = Router()

  router.get('/me/permissions', async (req, res) => {
    const session = req.session ?? { id: ANONYMOUS_SUBJECT_ID, companyId: null }
    const scope = session.companyId ?? undefined
    const checks = access.resources.flatMap((resource) => access.actions.map((action) => ({ action, resource, scope })))
    const map = await engine.permissions(session.id, checks)
    res.json({ subject: session.id, scope: scope ?? null, permissions: map })
  })

  return router
}
