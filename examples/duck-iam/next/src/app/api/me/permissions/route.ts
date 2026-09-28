import { route } from '@/auth'
import { access, getEngine } from '@/iam/iam'
import { sessionOf } from '@/session'

// One engine.permissions() call over the full action x resource matrix, so this can't drift
// from what the route guards actually enforce.
export const GET = route(async (req) => {
  const session = await sessionOf(req)
  const scope = session.companyId ?? undefined
  const checks = access.resources.flatMap((resource) => access.actions.map((action) => ({ action, resource, scope })))
  const map = await getEngine().permissions(session.id, checks)
  return Response.json({ subject: session.id, scope: scope ?? null, permissions: map })
})
