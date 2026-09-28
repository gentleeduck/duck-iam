import type { AppAuth } from '@examples/duck-iam-shared/auth'
import { resolveIdentityId } from '@examples/duck-iam-shared/auth'
import { ANONYMOUS_SUBJECT_ID } from '@examples/duck-iam-shared/iam'
import { users } from '@examples/duck-iam-shared/schema'
import { nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import { DUCK_AUTH_TOKEN } from '@gentleduck/auth/server/nestjs'
import { Inject, Injectable, type NestMiddleware } from '@nestjs/common'
import { eq } from 'drizzle-orm'
import type { NextFunction, Request, Response } from 'express'
import { db } from '../db'

// Stored on `req.user` (not `req.session`, which Nest's own session middleware would shadow) —
// the field `iamNestAccessGuard`'s default `getUserId` already reads.
declare global {
  namespace Express {
    interface Request {
      user?: SessionInfo
    }
  }
}

export interface SessionInfo {
  id: string
  companyId: string | null
}

@Injectable()
export class SessionMiddleware implements NestMiddleware {
  constructor(@Inject(DUCK_AUTH_TOKEN) private readonly auth: AppAuth) {}

  async use(req: Request, _res: Response, next: NextFunction): Promise<void> {
    const identityId = await resolveIdentityId(this.auth, nodeHeadersToFetch(req.headers))
    if (!identityId) {
      req.user = { id: ANONYMOUS_SUBJECT_ID, companyId: null }
      next()
      return
    }
    const [row] = await db.select().from(users).where(eq(users.id, identityId)).limit(1)
    req.user = row ? { id: row.id, companyId: row.companyId } : { id: ANONYMOUS_SUBJECT_ID, companyId: null }
    next()
  }
}

// Runtime-narrowed rather than cast: `req.user` here is `unknown` so this works whether the
// caller is duck-iam's own guard type or this app's augmented Express `Request`.
export function sessionOf(req: { user?: unknown }): SessionInfo | undefined {
  const user = req.user
  if (typeof user !== 'object' || user === null) return undefined
  if (!('id' in user) || typeof user.id !== 'string') return undefined
  const companyId = 'companyId' in user && typeof user.companyId === 'string' ? user.companyId : null
  return { id: user.id, companyId }
}
