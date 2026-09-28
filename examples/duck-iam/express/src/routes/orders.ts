import { randomUUID } from 'node:crypto'
import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { readInt, readString } from '@examples/duck-iam-shared/body'
import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { isOrderStatus, ORDER_STATUSES, orders, products } from '@examples/duck-iam-shared/schema'
import { expressCsrf } from '@gentleduck/auth/server/express'
import { iamGuard } from '@gentleduck/iam/server/express'
import { and, eq } from 'drizzle-orm'
import { Router } from 'express'
import { db } from '../db'
import { asHandler, paramId } from '../express-adapt'
import { sessionOf } from '../session'

export function ordersRouter(engine: AppEngine, auth: AppAuth) {
  const router = Router()
  router.use(expressCsrf(auth))
  const getUserId = (req: object) => sessionOf(req)?.id ?? null
  const getScope = (req: object) => sessionOf(req)?.companyId ?? undefined

  router.get('/', asHandler(iamGuard(engine, 'read', 'orders', { getUserId, getScope })), async (req, res) => {
    const companyId = sessionOf(req)?.companyId
    const rows = companyId ? await db.select().from(orders).where(eq(orders.companyId, companyId)) : []
    res.json(rows)
  })

  router.post('/', asHandler(iamGuard(engine, 'create', 'orders', { getUserId, getScope })), async (req, res) => {
    const session = sessionOf(req)
    const productId = readString(req.body, 'productId')
    const quantity = readInt(req.body, 'quantity', 1)
    if (!session?.companyId) return res.status(400).json({ error: 'caller has no company scope' })
    if (!productId || quantity === undefined) {
      return res.status(400).json({ error: 'productId (string) and quantity (positive integer) required' })
    }
    // Confirms the product belongs to the caller's own company before ordering it.
    const [product] = await db
      .select({ id: products.id })
      .from(products)
      .where(and(eq(products.id, productId), eq(products.companyId, session.companyId)))
      .limit(1)
    if (!product) return res.status(404).json({ error: 'no such product in your company' })
    const id = randomUUID()
    await db.insert(orders).values({ id, companyId: session.companyId, ownerId: session.id, productId, quantity })
    res.status(201).json({ id, companyId: session.companyId, ownerId: session.id, productId, quantity })
  })

  router.patch('/:id', asHandler(iamGuard(engine, 'update', 'orders', { getUserId, getScope })), async (req, res) => {
    const companyId = sessionOf(req)?.companyId
    if (!companyId) return res.status(404).json({ error: 'not found' })
    const status = readString(req.body, 'status')
    if (!status || !isOrderStatus(status)) {
      return res.status(400).json({ error: `status must be one of ${ORDER_STATUSES.join(', ')}` })
    }
    const updated = await db
      .update(orders)
      .set({ status })
      .where(and(eq(orders.id, paramId(req)), eq(orders.companyId, companyId)))
      .returning({ id: orders.id })
    if (updated.length === 0) return res.status(404).json({ error: 'not found' })
    res.json({ ok: true })
  })

  router.delete('/:id', asHandler(iamGuard(engine, 'delete', 'orders', { getUserId, getScope })), async (req, res) => {
    const companyId = sessionOf(req)?.companyId
    if (!companyId) return res.status(404).json({ error: 'not found' })
    const deleted = await db
      .delete(orders)
      .where(and(eq(orders.id, paramId(req)), eq(orders.companyId, companyId)))
      .returning({ id: orders.id })
    if (deleted.length === 0) return res.status(404).json({ error: 'not found' })
    res.json({ ok: true })
  })

  return router
}
