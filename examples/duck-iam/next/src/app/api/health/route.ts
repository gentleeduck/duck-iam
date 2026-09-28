import { route } from '@/auth'
import { getEngine } from '@/iam/iam'

// Unauthenticated on purpose: a load balancer or uptime probe hits this before it has a session.
export const GET = route(async (_req: Request) => {
  const health = await getEngine().healthCheck()
  return Response.json(health, { status: health.ok ? 200 : 503 })
})
