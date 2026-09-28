import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { readTrimmedString } from '@examples/duck-iam-shared/body'
import { companyHasUsers } from '@examples/duck-iam-shared/deletion-guards'
import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { companies } from '@examples/duck-iam-shared/schema'
import { honoCsrf, toHonoAdapterCtx } from '@gentleduck/auth/server/hono'
import { iamGuard } from '@gentleduck/iam/server/hono'
import { eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { db } from '../db'
import type { AppEnv } from '../session'
import { sessionOf } from '../session'

// IAM only checks the action/resource grant, not which row `:id` names — filter the row explicitly.
function isOwnCompany(c: { req: { param(name: string): string | undefined }; get(key: string): unknown }): boolean {
  return c.req.param('id') === sessionOf(c)?.companyId
}

export function companiesRouter(engine: AppEngine, auth: AppAuth) {
  const router = new Hono<AppEnv>()
  router.use((c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))
  const getUserId = (c: { get(key: string): unknown }) => sessionOf(c)?.id ?? null
  const getScope = (c: { get(key: string): unknown }) => sessionOf(c)?.companyId ?? undefined

  router.get('/:id', iamGuard(engine, 'read', 'companies', { getUserId, getScope }), async (c) => {
    if (!isOwnCompany(c)) return c.json({ error: 'not found' }, 404)
    const id = c.req.param('id')
    const [row] = await db.select().from(companies).where(eq(companies.id, id)).limit(1)
    if (!row) return c.json({ error: 'not found' }, 404)
    return c.json(row)
  })

  router.patch('/:id', iamGuard(engine, 'update', 'companies', { getUserId, getScope }), async (c) => {
    if (!isOwnCompany(c)) return c.json({ error: 'not found' }, 404)
    const body = await c.req.json<unknown>()
    const name = readTrimmedString(body, 'name')
    if (!name) return c.json({ error: 'name required' }, 400)
    await db
      .update(companies)
      .set({ name })
      .where(eq(companies.id, c.req.param('id')))
    return c.json({ ok: true })
  })

  router.delete('/:id', iamGuard(engine, 'delete', 'companies', { getUserId, getScope }), async (c) => {
    if (!isOwnCompany(c)) return c.json({ error: 'not found' }, 404)
    // Postgres would refuse this with an unhandled FK-violation 500 anyway (see deletion-guards.ts);
    // check first so the caller gets a clean, actionable response instead.
    if (await companyHasUsers(db, c.req.param('id'))) {
      return c.json({ error: 'cannot delete a company that still has users' }, 409)
    }
    await db.delete(companies).where(eq(companies.id, c.req.param('id')))
    return c.json({ ok: true })
  })

  return router
}
