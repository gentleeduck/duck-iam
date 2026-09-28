import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { Router } from 'express'

// Unauthenticated on purpose: a load balancer or uptime probe hits this before it has a session.
export function healthRouter(engine: AppEngine) {
  const router = Router()

  router.get('/health', async (_req, res) => {
    const health = await engine.healthCheck()
    res.status(health.ok ? 200 : 503).json(health)
  })

  return router
}
