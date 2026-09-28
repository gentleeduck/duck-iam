import { randomUUID } from 'node:crypto'
import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { readInt, readTrimmedString } from '@examples/duck-iam-shared/body'
import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { products } from '@examples/duck-iam-shared/schema'
import { honoCsrf, toHonoAdapterCtx } from '@gentleduck/auth/server/hono'
import { iamGuard } from '@gentleduck/iam/server/hono'
import { and, eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { db } from '../db'
import type { AppEnv } from '../session'
import { sessionOf } from '../session'

export function productsRouter(engine: AppEngine, auth: AppAuth) {
  const router = new Hono<AppEnv>()
  router.use((c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))
  const getUserId = (c: { get(key: string): unknown }) => sessionOf(c)?.id ?? null
  const getScope = (c: { get(key: string): unknown }) => sessionOf(c)?.companyId ?? undefined

  router.get('/', iamGuard(engine, 'read', 'products', { getUserId, getScope }), async (c) => {
    const companyId = sessionOf(c)?.companyId
    const rows = companyId ? await db.select().from(products).where(eq(products.companyId, companyId)) : []
    return c.json(rows)
  })

  router.post('/', iamGuard(engine, 'create', 'products', { getUserId, getScope }), async (c) => {
    const session = sessionOf(c)
    const body = await c.req.json<unknown>()
    const name = readTrimmedString(body, 'name')
    const priceCents = readInt(body, 'priceCents', 0)
    if (!session?.companyId) return c.json({ error: 'caller has no company scope' }, 400)
    if (!name || priceCents === undefined) {
      return c.json({ error: 'name (string) and priceCents (non-negative integer) required' }, 400)
    }
    const id = randomUUID()
    await db.insert(products).values({ id, companyId: session.companyId, ownerId: session.id, name, priceCents })
    return c.json({ id, companyId: session.companyId, ownerId: session.id, name, priceCents }, 201)
  })

  // Same tenant-filter reasoning as companies.ts.
  router.patch('/:id', iamGuard(engine, 'update', 'products', { getUserId, getScope }), async (c) => {
    const companyId = sessionOf(c)?.companyId
    if (!companyId) return c.json({ error: 'not found' }, 404)
    const body = await c.req.json<unknown>()
    const patch: { name?: string; priceCents?: number } = {}
    const name = readTrimmedString(body, 'name')
    const priceCents = readInt(body, 'priceCents', 0)
    if (name !== undefined) patch.name = name
    if (priceCents !== undefined) patch.priceCents = priceCents
    // drizzle's `.set({})` throws "No values to set" rather than a clean response.
    if (Object.keys(patch).length === 0) {
      return c.json({ error: 'name (string) or priceCents (non-negative integer) required' }, 400)
    }
    const updated = await db
      .update(products)
      .set(patch)
      .where(and(eq(products.id, c.req.param('id')), eq(products.companyId, companyId)))
      .returning({ id: products.id })
    if (updated.length === 0) return c.json({ error: 'not found' }, 404)
    return c.json({ ok: true })
  })

  router.delete('/:id', iamGuard(engine, 'delete', 'products', { getUserId, getScope }), async (c) => {
    const companyId = sessionOf(c)?.companyId
    if (!companyId) return c.json({ error: 'not found' }, 404)
    const deleted = await db
      .delete(products)
      .where(and(eq(products.id, c.req.param('id')), eq(products.companyId, companyId)))
      .returning({ id: products.id })
    if (deleted.length === 0) return c.json({ error: 'not found' }, 404)
    return c.json({ ok: true })
  })

  return router
}
