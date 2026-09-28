import { randomUUID } from 'node:crypto'
import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { readInt, readTrimmedString } from '@examples/duck-iam-shared/body'
import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { products } from '@examples/duck-iam-shared/schema'
import { expressCsrf } from '@gentleduck/auth/server/express'
import { iamGuard } from '@gentleduck/iam/server/express'
import { and, eq } from 'drizzle-orm'
import { Router } from 'express'
import { db } from '../db'
import { asHandler, paramId } from '../express-adapt'
import { sessionOf } from '../session'

export function productsRouter(engine: AppEngine, auth: AppAuth) {
  const router = Router()
  router.use(expressCsrf(auth))
  const getUserId = (req: object) => sessionOf(req)?.id ?? null
  const getScope = (req: object) => sessionOf(req)?.companyId ?? undefined

  router.get('/', asHandler(iamGuard(engine, 'read', 'products', { getUserId, getScope })), async (req, res) => {
    const companyId = sessionOf(req)?.companyId
    const rows = companyId ? await db.select().from(products).where(eq(products.companyId, companyId)) : []
    res.json(rows)
  })

  router.post('/', asHandler(iamGuard(engine, 'create', 'products', { getUserId, getScope })), async (req, res) => {
    const session = sessionOf(req)
    const name = readTrimmedString(req.body, 'name')
    const priceCents = readInt(req.body, 'priceCents', 0)
    if (!session?.companyId) return res.status(400).json({ error: 'caller has no company scope' })
    if (!name || priceCents === undefined) {
      return res.status(400).json({ error: 'name (string) and priceCents (non-negative integer) required' })
    }
    const id = randomUUID()
    await db.insert(products).values({ id, companyId: session.companyId, ownerId: session.id, name, priceCents })
    res.status(201).json({ id, companyId: session.companyId, ownerId: session.id, name, priceCents })
  })

  // Same tenant-filter reasoning as companies.ts.
  router.patch('/:id', asHandler(iamGuard(engine, 'update', 'products', { getUserId, getScope })), async (req, res) => {
    const companyId = sessionOf(req)?.companyId
    if (!companyId) return res.status(404).json({ error: 'not found' })
    const patch: { name?: string; priceCents?: number } = {}
    const name = readTrimmedString(req.body, 'name')
    const priceCents = readInt(req.body, 'priceCents', 0)
    if (name !== undefined) patch.name = name
    if (priceCents !== undefined) patch.priceCents = priceCents
    // drizzle's `.set({})` throws "No values to set" rather than a clean response.
    if (Object.keys(patch).length === 0) {
      return res.status(400).json({ error: 'name (string) or priceCents (non-negative integer) required' })
    }
    const updated = await db
      .update(products)
      .set(patch)
      .where(and(eq(products.id, paramId(req)), eq(products.companyId, companyId)))
      .returning({ id: products.id })
    if (updated.length === 0) return res.status(404).json({ error: 'not found' })
    res.json({ ok: true })
  })

  router.delete(
    '/:id',
    asHandler(iamGuard(engine, 'delete', 'products', { getUserId, getScope })),
    async (req, res) => {
      const companyId = sessionOf(req)?.companyId
      if (!companyId) return res.status(404).json({ error: 'not found' })
      const deleted = await db
        .delete(products)
        .where(and(eq(products.id, paramId(req)), eq(products.companyId, companyId)))
        .returning({ id: products.id })
      if (deleted.length === 0) return res.status(404).json({ error: 'not found' })
      res.json({ ok: true })
    },
  )

  return router
}
