import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { readString } from '@examples/duck-iam-shared/body'
import { userOwnsRows } from '@examples/duck-iam-shared/deletion-guards'
import { type AppEngine, access, isAppRole, setRole } from '@examples/duck-iam-shared/iam'
import { users } from '@examples/duck-iam-shared/schema'
import { expressCsrf } from '@gentleduck/auth/server/express'
import { iamGuard } from '@gentleduck/iam/server/express'
import { and, eq } from 'drizzle-orm'
import { Router } from 'express'
import { db } from '../db'
import { asHandler, paramId } from '../express-adapt'
import { sessionOf } from '../session'

export function usersRouter(engine: AppEngine, auth: AppAuth) {
  const router = Router()
  router.use(expressCsrf(auth))
  const getUserId = (req: object) => sessionOf(req)?.id ?? null
  const getScope = (req: object) => sessionOf(req)?.companyId ?? undefined

  router.get('/', asHandler(iamGuard(engine, 'read', 'users', { getUserId, getScope })), async (req, res) => {
    const companyId = sessionOf(req)?.companyId
    const rows = companyId ? await db.select().from(users).where(eq(users.companyId, companyId)) : []
    res.json(rows)
  })

  // Same tenant-filter reasoning as companies.ts: the row's companyId must match too.
  router.get('/:id', asHandler(iamGuard(engine, 'read', 'users', { getUserId, getScope })), async (req, res) => {
    const companyId = sessionOf(req)?.companyId
    if (!companyId) return res.status(404).json({ error: 'not found' })
    const [row] = await db
      .select()
      .from(users)
      .where(and(eq(users.id, paramId(req)), eq(users.companyId, companyId)))
      .limit(1)
    if (!row) return res.status(404).json({ error: 'not found' })
    res.json(row)
  })

  // `deny-self-account-delete` blocks this when the target row is the caller's own.
  router.delete(
    '/:id',
    asHandler(
      iamGuard(engine, 'delete', 'users', {
        getUserId,
        getScope,
        getResourceAttributes: (req) => ({ id: req.params?.id ?? '' }),
      }),
    ),
    async (req, res) => {
      const companyId = sessionOf(req)?.companyId
      if (!companyId) return res.status(404).json({ error: 'not found' })
      // Same FK-violation reasoning as companies.ts: check before the DB refuses it the hard way.
      if (await userOwnsRows(db, paramId(req))) {
        return res.status(409).json({ error: 'cannot delete a user who owns products or orders' })
      }
      const deleted = await db
        .delete(users)
        .where(and(eq(users.id, paramId(req)), eq(users.companyId, companyId)))
        .returning({ id: users.id })
      if (deleted.length === 0) return res.status(404).json({ error: 'not found' })
      res.json({ ok: true })
    },
  )

  router.post(
    '/:id/role',
    asHandler(iamGuard(engine, 'manageRoles', 'users', { getUserId, getScope })),
    async (req, res) => {
      const roleId = readString(req.body, 'roleId')
      const scope = sessionOf(req)?.companyId
      if (!isAppRole(roleId)) return res.status(400).json({ error: `roleId must be one of ${access.roles.join(', ')}` })
      if (!scope) return res.status(400).json({ error: 'caller has no company scope' })
      const [target] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.id, paramId(req)), eq(users.companyId, scope)))
        .limit(1)
      if (!target) return res.status(404).json({ error: 'not found' })
      await setRole(engine, db, paramId(req), roleId, scope)
      res.json({ ok: true, userId: paramId(req), roleId, scope })
    },
  )

  return router
}
