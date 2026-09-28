import { randomUUID } from 'node:crypto'
import { readInt, readString } from '@examples/duck-iam-shared/body'
import { orders, products } from '@examples/duck-iam-shared/schema'
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

export const GET = route(
  withIamAccess(
    getEngine(),
    'read',
    'orders',
    async (req) => {
      const companyId = (await sessionOf(req)).companyId
      const rows = companyId ? await db.select().from(orders).where(eq(orders.companyId, companyId)) : []
      return Response.json(rows)
    },
    guardOpts,
  ),
)

export const POST = route(
  withIamAccess(
    getEngine(),
    'create',
    'orders',
    async (req) => {
      const session = await sessionOf(req)
      const body: unknown = await req.json().catch(() => undefined)
      const productId = readString(body, 'productId')
      const quantity = readInt(body, 'quantity', 1)
      if (!session.companyId) return Response.json({ error: 'caller has no company scope' }, { status: 400 })
      if (!productId || quantity === undefined) {
        return Response.json({ error: 'productId (string) and quantity (positive integer) required' }, { status: 400 })
      }
      // Confirms the product belongs to the caller's own company before ordering it.
      const [product] = await db
        .select({ id: products.id })
        .from(products)
        .where(and(eq(products.id, productId), eq(products.companyId, session.companyId)))
        .limit(1)
      if (!product) return Response.json({ error: 'no such product in your company' }, { status: 404 })
      const id = randomUUID()
      await db.insert(orders).values({ id, companyId: session.companyId, ownerId: session.id, productId, quantity })
      return Response.json(
        { id, companyId: session.companyId, ownerId: session.id, productId, quantity },
        { status: 201 },
      )
    },
    guardOpts,
  ),
)
