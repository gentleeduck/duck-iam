import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { readString } from '@examples/duck-iam-shared/body'
import { userOwnsRows } from '@examples/duck-iam-shared/deletion-guards'
import { type AppEngine, access, isAppRole, setRole } from '@examples/duck-iam-shared/iam'
import { users } from '@examples/duck-iam-shared/schema'
import { honoCsrf, toHonoAdapterCtx } from '@gentleduck/auth/server/hono'
import { iamGuard } from '@gentleduck/iam/server/hono'
import { and, eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { db } from '../db'
import type { AppEnv } from '../session'
import { sessionOf } from '../session'

export function usersRouter(engine: AppEngine, auth: AppAuth) {
  const router = new Hono<AppEnv>()
  router.use((c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))
  const getUserId = (c: { get(key: string): unknown }) => sessionOf(c)?.id ?? null
  const getScope = (c: { get(key: string): unknown }) => sessionOf(c)?.companyId ?? undefined

  router.get('/', iamGuard(engine, 'read', 'users', { getUserId, getScope }), async (c) => {
    const companyId = sessionOf(c)?.companyId
    const rows = companyId ? await db.select().from(users).where(eq(users.companyId, companyId)) : []
    return c.json(rows)
  })

  // Same tenant-filter reasoning as companies.ts.
  router.get('/:id', iamGuard(engine, 'read', 'users', { getUserId, getScope }), async (c) => {
    const companyId = sessionOf(c)?.companyId
    if (!companyId) return c.json({ error: 'not found' }, 404)
    const [row] = await db
      .select()
      .from(users)
      .where(and(eq(users.id, c.req.param('id')), eq(users.companyId, companyId)))
      .limit(1)
    if (!row) return c.json({ error: 'not found' }, 404)
    return c.json(row)
  })

  // `deny-self-account-delete` blocks this when the target row is the caller's own.
  router.delete(
    '/:id',
    iamGuard(engine, 'delete', 'users', {
      getUserId,
      getScope,
      getResourceAttributes: (c) => ({ id: c.req.param('id') ?? '' }),
    }),
    async (c) => {
      const companyId = sessionOf(c)?.companyId
      if (!companyId) return c.json({ error: 'not found' }, 404)
      // Same FK-violation reasoning as companies.ts: check before the DB refuses it the hard way.
      if (await userOwnsRows(db, c.req.param('id'))) {
        return c.json({ error: 'cannot delete a user who owns products or orders' }, 409)
      }
      const deleted = await db
        .delete(users)
        .where(and(eq(users.id, c.req.param('id')), eq(users.companyId, companyId)))
        .returning({ id: users.id })
      if (deleted.length === 0) return c.json({ error: 'not found' }, 404)
      return c.json({ ok: true })
    },
  )

  router.post('/:id/role', iamGuard(engine, 'manageRoles', 'users', { getUserId, getScope }), async (c) => {
    const body = await c.req.json<unknown>()
    const roleId = readString(body, 'roleId')
    const scope = sessionOf(c)?.companyId
    const targetId = c.req.param('id')
    if (!isAppRole(roleId)) return c.json({ error: `roleId must be one of ${access.roles.join(', ')}` }, 400)
    if (!scope) return c.json({ error: 'caller has no company scope' }, 400)
    const [target] = await db
      .select({ id: users.id })
      .from(users)
      .where(and(eq(users.id, targetId), eq(users.companyId, scope)))
      .limit(1)
    if (!target) return c.json({ error: 'not found' }, 404)
    await setRole(engine, db, targetId, roleId, scope)
    return c.json({ ok: true, userId: targetId, roleId, scope })
  })

  return router
}
