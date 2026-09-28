import { resolveIdentityId } from '@examples/duck-iam-shared/auth'
import { ANONYMOUS_SUBJECT_ID } from '@examples/duck-iam-shared/iam'
import { users } from '@examples/duck-iam-shared/schema'
import { eq } from 'drizzle-orm'
import { auth } from './auth'
import { db } from './db'

export interface SessionInfo {
  id: string
  companyId: string | null
}

async function resolveSession(req: Request): Promise<SessionInfo> {
  const identityId = await resolveIdentityId(auth, req.headers)
  if (!identityId) return { id: ANONYMOUS_SUBJECT_ID, companyId: null }

  const [row] = await db.select().from(users).where(eq(users.id, identityId)).limit(1)
  return row ? { id: row.id, companyId: row.companyId } : { id: ANONYMOUS_SUBJECT_ID, companyId: null }
}

// Keyed on the request so the session cookie is resolved against the db at most once per request.
const asyncCache = new WeakMap<Request, Promise<SessionInfo>>()
const syncCache = new WeakMap<Request, SessionInfo>()

export function sessionOf(req: Request): Promise<SessionInfo> {
  let cached = asyncCache.get(req)
  if (!cached) {
    cached = resolveSession(req).then((session) => {
      syncCache.set(req, session)
      return session
    })
    asyncCache.set(req, cached)
  }
  return cached
}

// `getScope` is synchronous; safe here because `withIamAccess` always awaits `getUserId` (built
// from `sessionOf`) before evaluating `getScope`, so the cache is already populated.
export function sessionOfSync(req: Request): SessionInfo | undefined {
  return syncCache.get(req)
}
