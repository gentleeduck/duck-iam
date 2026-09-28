import { resolveIdentityId } from '@examples/duck-iam-shared/auth'
import { ANONYMOUS_SUBJECT_ID } from '@examples/duck-iam-shared/iam'
import { users } from '@examples/duck-iam-shared/schema'
import { toHeaders } from '@gentleduck/auth/server/express'
import { eq } from 'drizzle-orm'
import type { NextFunction, Request, Response } from 'express'
import { auth } from './auth'
import { db } from './db'

declare global {
  namespace Express {
    interface Request {
      session?: { id: string; companyId: string | null }
    }
  }
}

export interface SessionInfo {
  id: string
  companyId: string | null
}

// Runtime-narrowed rather than cast: duck-iam's `iamGuard` sees the request only through its own
// minimal `Req` shape, not this app's augmented Express `Request`.
export function sessionOf(req: object): SessionInfo | undefined {
  if (!('session' in req)) return undefined
  const session = req.session
  if (typeof session !== 'object' || session === null) return undefined
  if (!('id' in session) || typeof session.id !== 'string') return undefined
  const companyId = 'companyId' in session && typeof session.companyId === 'string' ? session.companyId : null
  return { id: session.id, companyId }
}

export async function attachSession(req: Request, _res: Response, next: NextFunction): Promise<void> {
  const identityId = await resolveIdentityId(auth, toHeaders(req.headers))

  if (!identityId) {
    req.session = { id: ANONYMOUS_SUBJECT_ID, companyId: null }
    next()
    return
  }

  const [row] = await db.select().from(users).where(eq(users.id, identityId)).limit(1)
  req.session = row ? { id: row.id, companyId: row.companyId } : { id: ANONYMOUS_SUBJECT_ID, companyId: null }
  next()
}
