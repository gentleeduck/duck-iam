import { randomUUID } from 'node:crypto'
import { readInt, readTrimmedString } from '@examples/duck-iam-shared/body'
import { products } from '@examples/duck-iam-shared/schema'
import { withIamAccess } from '@gentleduck/iam/server/next'
import { eq } from 'drizzle-orm'
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
    'products',
    async (req) => {
      const companyId = (await sessionOf(req)).companyId
      const rows = companyId ? await db.select().from(products).where(eq(products.companyId, companyId)) : []
      return Response.json(rows)
    },
    guardOpts,
  ),
)

export const POST = route(
  withIamAccess(
    getEngine(),
    'create',
    'products',
    async (req) => {
      const session = await sessionOf(req)
      const body: unknown = await req.json().catch(() => undefined)
      const name = readTrimmedString(body, 'name')
      const priceCents = readInt(body, 'priceCents', 0)
      if (!session.companyId) return Response.json({ error: 'caller has no company scope' }, { status: 400 })
      if (!name || priceCents === undefined) {
        return Response.json({ error: 'name (string) and priceCents (non-negative integer) required' }, { status: 400 })
      }
      const id = randomUUID()
      await db.insert(products).values({ id, companyId: session.companyId, ownerId: session.id, name, priceCents })
      return Response.json({ id, companyId: session.companyId, ownerId: session.id, name, priceCents }, { status: 201 })
    },
    guardOpts,
  ),
)
