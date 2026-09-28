import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { readTrimmedString } from '@examples/duck-iam-shared/body'
import { companyHasUsers } from '@examples/duck-iam-shared/deletion-guards'
import type { AppEngine } from '@examples/duck-iam-shared/iam'
import { companies } from '@examples/duck-iam-shared/schema'
import { expressCsrf } from '@gentleduck/auth/server/express'
import { iamGuard } from '@gentleduck/iam/server/express'
import { eq } from 'drizzle-orm'
import { type Request, type Response, Router } from 'express'
import { db } from '../db'
import { asHandler, paramId } from '../express-adapt'
import { sessionOf } from '../session'

// IAM only checks the action/resource grant, not which row `:id` names — a company-acme viewer
// would otherwise read company-globex just by guessing its id. Filter the row explicitly.
function isOwnCompany(req: Request, res: Response): boolean {
  if (paramId(req) !== sessionOf(req)?.companyId) {
    res.status(404).json({ error: 'not found' })
    return false
  }
  return true
}

export function companiesRouter(engine: AppEngine, auth: AppAuth) {
  const router = Router()
  router.use(expressCsrf(auth))
  const getUserId = (req: object) => sessionOf(req)?.id ?? null
  const getScope = (req: object) => sessionOf(req)?.companyId ?? undefined

  router.get('/:id', asHandler(iamGuard(engine, 'read', 'companies', { getUserId, getScope })), async (req, res) => {
    if (!isOwnCompany(req, res)) return
    const [row] = await db
      .select()
      .from(companies)
      .where(eq(companies.id, paramId(req)))
      .limit(1)
    if (!row) return res.status(404).json({ error: 'not found' })
    res.json(row)
  })

  router.patch(
    '/:id',
    asHandler(iamGuard(engine, 'update', 'companies', { getUserId, getScope })),
    async (req, res) => {
      if (!isOwnCompany(req, res)) return
      const name = readTrimmedString(req.body, 'name')
      if (!name) return res.status(400).json({ error: 'name required' })
      await db
        .update(companies)
        .set({ name })
        .where(eq(companies.id, paramId(req)))
      res.json({ ok: true })
    },
  )

  router.delete(
    '/:id',
    asHandler(iamGuard(engine, 'delete', 'companies', { getUserId, getScope })),
    async (req, res) => {
      if (!isOwnCompany(req, res)) return
      // Postgres would refuse this with an unhandled FK-violation 500 anyway (see deletion-guards.ts);
      // check first so the caller gets a clean, actionable response instead.
      if (await companyHasUsers(db, paramId(req))) {
        return res.status(409).json({ error: 'cannot delete a company that still has users' })
      }
      await db.delete(companies).where(eq(companies.id, paramId(req)))
      res.json({ ok: true })
    },
  )

  return router
}
