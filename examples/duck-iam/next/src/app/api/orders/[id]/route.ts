import { readString } from '@examples/duck-iam-shared/body'
import { isOrderStatus, ORDER_STATUSES, orders } from '@examples/duck-iam-shared/schema'
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

export const PATCH = route(
  withIamAccess(
    getEngine(),
    'update',
    'orders',
    async (req, ctx) => {
      const { id } = await ctx.params
      const companyId = (await sessionOf(req)).companyId
      if (!companyId) return Response.json({ error: 'not found' }, { status: 404 })
      const status = readString(await req.json().catch(() => undefined), 'status')
      if (!status || !isOrderStatus(status)) {
        return Response.json({ error: `status must be one of ${ORDER_STATUSES.join(', ')}` }, { status: 400 })
      }
      const updated = await db
        .update(orders)
        .set({ status })
        .where(and(eq(orders.id, id), eq(orders.companyId, companyId)))
        .returning({ id: orders.id })
      if (updated.length === 0) return Response.json({ error: 'not found' }, { status: 404 })
      return Response.json({ ok: true })
    },
    guardOpts,
  ),
)

export const DELETE = route(
  withIamAccess(
    getEngine(),
    'delete',
    'orders',
    async (req, ctx) => {
      const { id } = await ctx.params
      const companyId = (await sessionOf(req)).companyId
      if (!companyId) return Response.json({ error: 'not found' }, { status: 404 })
      const deleted = await db
        .delete(orders)
        .where(and(eq(orders.id, id), eq(orders.companyId, companyId)))
        .returning({ id: orders.id })
      if (deleted.length === 0) return Response.json({ error: 'not found' }, { status: 404 })
      return Response.json({ ok: true })
    },
    guardOpts,
  ),
)
