import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { Hono } from 'hono'

// Unauthenticated on purpose: a load balancer or uptime probe hits this before it has a session.
export function healthRouter(engine: AppEngine) {
  const router = new Hono()

  router.get('/health', async (c) => {
    const health = await engine.healthCheck()
    return c.json(health, health.ok ? 200 : 503)
  })

  return router
}
