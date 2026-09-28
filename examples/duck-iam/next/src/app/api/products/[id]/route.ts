import { readInt, readTrimmedString } from '@examples/duck-iam-shared/body'
import { products } from '@examples/duck-iam-shared/schema'
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

// Same tenant-filter reasoning as companies/[id].
export const PATCH = route(
  withIamAccess(
    getEngine(),
    'update',
    'products',
    async (req, ctx) => {
      const { id } = await ctx.params
      const companyId = (await sessionOf(req)).companyId
      if (!companyId) return Response.json({ error: 'not found' }, { status: 404 })
      const body: unknown = await req.json().catch(() => undefined)
      const patch: { name?: string; priceCents?: number } = {}
      const name = readTrimmedString(body, 'name')
      const priceCents = readInt(body, 'priceCents', 0)
      if (name !== undefined) patch.name = name
      if (priceCents !== undefined) patch.priceCents = priceCents
      // drizzle's `.set({})` throws "No values to set" rather than a clean response.
      if (Object.keys(patch).length === 0) {
        return Response.json({ error: 'name (string) or priceCents (non-negative integer) required' }, { status: 400 })
      }
      const updated = await db
        .update(products)
        .set(patch)
        .where(and(eq(products.id, id), eq(products.companyId, companyId)))
        .returning({ id: products.id })
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
    'products',
    async (req, ctx) => {
      const { id } = await ctx.params
      const companyId = (await sessionOf(req)).companyId
      if (!companyId) return Response.json({ error: 'not found' }, { status: 404 })
      const deleted = await db
        .delete(products)
        .where(and(eq(products.id, id), eq(products.companyId, companyId)))
        .returning({ id: products.id })
      if (deleted.length === 0) return Response.json({ error: 'not found' }, { status: 404 })
      return Response.json({ ok: true })
    },
    guardOpts,
  ),
)
