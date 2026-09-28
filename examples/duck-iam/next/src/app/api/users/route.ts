import { users } from '@examples/duck-iam-shared/schema'
import { withIamAccess } from '@gentleduck/iam/server/next'
import { eq } from 'drizzle-orm'
import { route } from '@/auth'
import { db } from '@/db'
import { getEngine } from '@/iam/iam'
import { sessionOf, sessionOfSync } from '@/session'

export const GET = route(
  withIamAccess(
    getEngine(),
    'read',
    'users',
    async (req) => {
      const companyId = (await sessionOf(req)).companyId
      const rows = companyId ? await db.select().from(users).where(eq(users.companyId, companyId)) : []
      return Response.json(rows)
    },
    {
      getUserId: async (req) => (await sessionOf(req)).id,
      getScope: (req) => sessionOfSync(req)?.companyId ?? undefined,
    },
  ),
)
