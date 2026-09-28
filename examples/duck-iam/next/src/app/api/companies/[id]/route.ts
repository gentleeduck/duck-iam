import { readTrimmedString } from '@examples/duck-iam-shared/body'
import { companyHasUsers } from '@examples/duck-iam-shared/deletion-guards'
import { companies } from '@examples/duck-iam-shared/schema'
import { withIamAccess } from '@gentleduck/iam/server/next'
import { eq } from 'drizzle-orm'
import { route } from '@/auth'
import { db } from '@/db'
import { getEngine } from '@/iam/iam'
import { sessionOf, sessionOfSync } from '@/session'

// IAM only checks the action/resource grant, not which row `:id` names — filter the row explicitly.
async function isOwnCompany(req: Request, id: string): Promise<boolean> {
  return id === (await sessionOf(req)).companyId
}

const guardOpts = {
  getUserId: async (req: Request) => (await sessionOf(req)).id,
  getScope: (req: Request) => sessionOfSync(req)?.companyId ?? undefined,
}

export const GET = route(
  withIamAccess(
    getEngine(),
    'read',
    'companies',
    async (req, ctx) => {
      const { id } = await ctx.params
      if (!(await isOwnCompany(req, id))) return Response.json({ error: 'not found' }, { status: 404 })
      const [row] = await db.select().from(companies).where(eq(companies.id, id)).limit(1)
      if (!row) return Response.json({ error: 'not found' }, { status: 404 })
      return Response.json(row)
    },
    guardOpts,
  ),
)

export const PATCH = route(
  withIamAccess(
    getEngine(),
    'update',
    'companies',
    async (req, ctx) => {
      const { id } = await ctx.params
      if (!(await isOwnCompany(req, id))) return Response.json({ error: 'not found' }, { status: 404 })
      const name = readTrimmedString(await req.json().catch(() => undefined), 'name')
      if (!name) return Response.json({ error: 'name required' }, { status: 400 })
      await db.update(companies).set({ name }).where(eq(companies.id, id))
      return Response.json({ ok: true })
    },
    guardOpts,
  ),
)

export const DELETE = route(
  withIamAccess(
    getEngine(),
    'delete',
    'companies',
    async (req, ctx) => {
      const { id } = await ctx.params
      if (!(await isOwnCompany(req, id))) return Response.json({ error: 'not found' }, { status: 404 })
      // Postgres would refuse this with an unhandled FK-violation 500 anyway (see deletion-guards.ts);
      // check first so the caller gets a clean, actionable response instead.
      if (await companyHasUsers(db, id)) {
        return Response.json({ error: 'cannot delete a company that still has users' }, { status: 409 })
      }
      await db.delete(companies).where(eq(companies.id, id))
      return Response.json({ ok: true })
    },
    guardOpts,
  ),
)
