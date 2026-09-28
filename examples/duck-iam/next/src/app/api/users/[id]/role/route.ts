import { readString } from '@examples/duck-iam-shared/body'
import { access, isAppRole, setRole } from '@examples/duck-iam-shared/iam'
import { users } from '@examples/duck-iam-shared/schema'
import { withIamAccess } from '@gentleduck/iam/server/next'
import { and, eq } from 'drizzle-orm'
import { route } from '@/auth'
import { db } from '@/db'
import { getEngine } from '@/iam/iam'
import { sessionOf, sessionOfSync } from '@/session'

export const POST = route(
  withIamAccess(
    getEngine(),
    'manageRoles',
    'users',
    async (req, ctx) => {
      const { id: targetId } = await ctx.params
      const session = await sessionOf(req)
      const scope = session.companyId
      const roleId = readString(await req.json().catch(() => undefined), 'roleId')
      if (!isAppRole(roleId)) {
        return Response.json({ error: `roleId must be one of ${access.roles.join(', ')}` }, { status: 400 })
      }
      if (!scope) return Response.json({ error: 'caller has no company scope' }, { status: 400 })

      const [target] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.id, targetId), eq(users.companyId, scope)))
        .limit(1)
      if (!target) return Response.json({ error: 'not found' }, { status: 404 })

      await setRole(getEngine(), db, targetId, roleId, scope)
      return Response.json({ ok: true, userId: targetId, roleId, scope })
    },
    {
      getUserId: async (req) => (await sessionOf(req)).id,
      getScope: (req) => sessionOfSync(req)?.companyId ?? undefined,
    },
  ),
)
