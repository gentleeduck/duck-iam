import { randomUUID } from 'node:crypto'
import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { readInt, readString } from '@examples/duck-iam-shared/body'
import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { isOrderStatus, ORDER_STATUSES, orders, products } from '@examples/duck-iam-shared/schema'
import { honoCsrf, toHonoAdapterCtx } from '@gentleduck/auth/server/hono'
import { iamGuard } from '@gentleduck/iam/server/hono'
import { and, eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { db } from '../db'
import type { AppEnv } from '../session'
import { sessionOf } from '../session'

export function ordersRouter(engine: AppEngine, auth: AppAuth) {
  const router = new Hono<AppEnv>()
  router.use((c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))
  const getUserId = (c: { get(key: string): unknown }) => sessionOf(c)?.id ?? null
  const getScope = (c: { get(key: string): unknown }) => sessionOf(c)?.companyId ?? undefined

  router.get('/', iamGuard(engine, 'read', 'orders', { getUserId, getScope }), async (c) => {
    const companyId = sessionOf(c)?.companyId
    const rows = companyId ? await db.select().from(orders).where(eq(orders.companyId, companyId)) : []
    return c.json(rows)
  })

  router.post('/', iamGuard(engine, 'create', 'orders', { getUserId, getScope }), async (c) => {
    const session = sessionOf(c)
    const body = await c.req.json<unknown>()
    const productId = readString(body, 'productId')
    const quantity = readInt(body, 'quantity', 1)
    if (!session?.companyId) return c.json({ error: 'caller has no company scope' }, 400)
    if (!productId || quantity === undefined) {
      return c.json({ error: 'productId (string) and quantity (positive integer) required' }, 400)
    }
    // Confirms the product belongs to the caller's own company before ordering it.
    const [product] = await db
      .select({ id: products.id })
      .from(products)
      .where(and(eq(products.id, productId), eq(products.companyId, session.companyId)))
      .limit(1)
    if (!product) return c.json({ error: 'no such product in your company' }, 404)
    const id = randomUUID()
    await db.insert(orders).values({ id, companyId: session.companyId, ownerId: session.id, productId, quantity })
    return c.json({ id, companyId: session.companyId, ownerId: session.id, productId, quantity }, 201)
  })

  router.patch('/:id', iamGuard(engine, 'update', 'orders', { getUserId, getScope }), async (c) => {
    const companyId = sessionOf(c)?.companyId
    if (!companyId) return c.json({ error: 'not found' }, 404)
    const body = await c.req.json<unknown>()
    const status = readString(body, 'status')
    if (!status || !isOrderStatus(status)) {
      return c.json({ error: `status must be one of ${ORDER_STATUSES.join(', ')}` }, 400)
    }
    const updated = await db
      .update(orders)
      .set({ status })
      .where(and(eq(orders.id, c.req.param('id')), eq(orders.companyId, companyId)))
      .returning({ id: orders.id })
    if (updated.length === 0) return c.json({ error: 'not found' }, 404)
    return c.json({ ok: true })
  })

  router.delete('/:id', iamGuard(engine, 'delete', 'orders', { getUserId, getScope }), async (c) => {
    const companyId = sessionOf(c)?.companyId
    if (!companyId) return c.json({ error: 'not found' }, 404)
    const deleted = await db
      .delete(orders)
      .where(and(eq(orders.id, c.req.param('id')), eq(orders.companyId, companyId)))
      .returning({ id: orders.id })
    if (deleted.length === 0) return c.json({ error: 'not found' }, 404)
    return c.json({ ok: true })
  })

  return router
}
