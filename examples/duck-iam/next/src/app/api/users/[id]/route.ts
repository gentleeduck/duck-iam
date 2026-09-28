import { userOwnsRows } from '@examples/duck-iam-shared/deletion-guards'
import { users } from '@examples/duck-iam-shared/schema'
import { withIamAccess } from '@gentleduck/iam/server/next'
import { and, eq } from 'drizzle-orm'
import { route } from '@/auth'
import { db } from '@/db'
import { getEngine } from '@/iam/iam'
import { sessionOf, sessionOfSync } from '@/session'

const guardOpts = {
  getUserId: async (req: Request) => (await sessionOf(req)).id,
  getScope: (req: Request) => sessionOfSync(req)?.companyId ?? undefined,
}

// Same tenant-filter reasoning as companies/[id]/route.ts.
export const GET = route(
  withIamAccess(
    getEngine(),
    'read',
    'users',
    async (req, ctx) => {
      const { id } = await ctx.params
      const companyId = (await sessionOf(req)).companyId
      if (!companyId) return Response.json({ error: 'not found' }, { status: 404 })
      const [row] = await db
        .select()
        .from(users)
        .where(and(eq(users.id, id), eq(users.companyId, companyId)))
        .limit(1)
      if (!row) return Response.json({ error: 'not found' }, { status: 404 })
      return Response.json(row)
    },
    guardOpts,
  ),
)

// `deny-self-account-delete` blocks this when the target row is the caller's own.
export const DELETE = route(
  withIamAccess(
    getEngine(),
    'delete',
    'users',
    async (req, ctx) => {
      const { id } = await ctx.params
      const companyId = (await sessionOf(req)).companyId
      if (!companyId) return Response.json({ error: 'not found' }, { status: 404 })
      // Same FK-violation reasoning as companies/[id]/route.ts: check before the DB refuses it the hard way.
      if (await userOwnsRows(db, id)) {
        return Response.json({ error: 'cannot delete a user who owns products or orders' }, { status: 409 })
      }
      const deleted = await db
        .delete(users)
        .where(and(eq(users.id, id), eq(users.companyId, companyId)))
        .returning({ id: users.id })
      if (deleted.length === 0) return Response.json({ error: 'not found' }, { status: 404 })
      return Response.json({ ok: true })
    },
    {
      getUserId: guardOpts.getUserId,
      getScope: guardOpts.getScope,
      getResourceAttributes: (_req, ctx) => ({ id: ctx.resourceId ?? '' }),
    },
  ),
)
