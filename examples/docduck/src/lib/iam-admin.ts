/**
 * The gate every `/api/iam/*` devtools route runs before it touches the
 * engine.
 *
 * These routes expose the whole authorization model - every policy, every
 * role, any subject's attributes - and the subjects panel writes through them.
 * So the gate is two independent conditions, both required:
 *
 *   1. the build is not production, and
 *   2. the caller has a real better-auth session.
 *
 * The devtools component carries its own production guard, but that one runs
 * in the browser and a guard in the browser protects nothing: the routes are
 * reachable with `curl` whether or not anything renders. This is the check
 * that matters.
 */
import { iamDefaultCsrfCheck, iamRunAdminAuthz } from '@gentleduck/iam/server/generic'
import { createIamAdminHandlers } from '@gentleduck/iam/server/next'
import { headers } from 'next/headers'
import { engine } from './access'
import { auth } from './auth'

/**
 * Whether the IAM devtools may be mounted and its routes may answer.
 *
 * Read at module load, which is when Next inlines `process.env.NODE_ENV`, so
 * the production build drops the mount entirely rather than shipping a
 * component that decides at runtime.
 */
export const IAM_DEVTOOLS_ENABLED = process.env.NODE_ENV !== 'production'

/**
 * Returns a boolean rather than the session user, which is what
 * `IamNext.IAdminAuthorize` declares. duck-iam's audit trail would rather have
 * the actor - it warns once that a boolean names nobody - but the published
 * type does not admit one, so a boolean is what an in-contract consumer can
 * return.
 */
async function authorizeIamAdmin(): Promise<boolean> {
  if (!IAM_DEVTOOLS_ENABLED) return false
  const session = await auth.api.getSession({ headers: await headers() })
  return Boolean(session?.user)
}

/** The six admin endpoints duck-iam ships for Next. */
export const iamAdminHandlers = createIamAdminHandlers(engine, { authorize: authorizeIamAdmin })

/**
 * The same gate, for the endpoints duck-iam does not ship a handler for.
 *
 * `IamHttpAdapter` reads a subject's roles, scoped roles and attributes -
 * `engine.explain()` cannot resolve a subject without all three - but
 * `createIamAdminHandlers` covers only policies, roles and role assignment.
 * The five that remain - the three reads above, the attribute write, and a
 * revoke that honours `?scope=` - are written out under
 * `app/api/iam/subjects/`, and they run this so they refuse exactly what the
 * shipped handlers refuse: the same CSRF predicate, the same `authorize`, the
 * same status codes.
 */
export async function iamAdminRoute(req: Request, run: () => Promise<unknown>): Promise<Response> {
  const authz = await iamRunAdminAuthz(req, iamDefaultCsrfCheck, authorizeIamAdmin)
  if (authz.phase === 'forbidden') return Response.json({ error: 'Forbidden (CSRF check failed)' }, { status: 403 })
  if (authz.phase === 'unauthorized') return Response.json({ error: 'Unauthorized' }, { status: 401 })
  if (authz.phase === 'error') return Response.json({ error: 'Internal server error' }, { status: 500 })
  try {
    // A handler that needs to answer something other than 200 - a 400 for a
    // body this app rejects before the engine sees it - returns the response
    // itself. Anything else is the JSON payload.
    const value = await run()
    return value instanceof Response ? value : Response.json(value)
  } catch (err) {
    console.error('[docduck:iam-admin]', err)
    return Response.json({ error: 'Internal server error' }, { status: 500 })
  }
}
