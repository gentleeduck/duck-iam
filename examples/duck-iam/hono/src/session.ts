import { resolveIdentityId } from '@examples/duck-iam-shared/auth'
import { ANONYMOUS_SUBJECT_ID } from '@examples/duck-iam-shared/iam'
import { users } from '@examples/duck-iam-shared/schema'
import { eq } from 'drizzle-orm'
import type { Context, Next } from 'hono'
import { auth } from './auth'
import { db } from './db'

export interface SessionInfo {
  id: string
  companyId: string | null
}

export type AppEnv = { Variables: { session: SessionInfo } }

export async function attachSession(c: Context<AppEnv>, next: Next): Promise<void> {
  const identityId = await resolveIdentityId(auth, c.req.raw.headers)

  if (!identityId) {
    c.set('session', { id: ANONYMOUS_SUBJECT_ID, companyId: null })
    await next()
    return
  }

  const [row] = await db.select().from(users).where(eq(users.id, identityId)).limit(1)
  c.set('session', row ? { id: row.id, companyId: row.companyId } : { id: ANONYMOUS_SUBJECT_ID, companyId: null })
  await next()
}

// Runtime-narrowed rather than cast: duck-iam's `iamGuard` sees the context only through its own
// minimal shape (`get(key): unknown`), not this app's typed `Context<AppEnv>`.
export function sessionOf(c: { get(key: string): unknown }): SessionInfo | undefined {
  const session = c.get('session')
  if (typeof session !== 'object' || session === null) return undefined
  if (!('id' in session) || typeof session.id !== 'string') return undefined
  const companyId = 'companyId' in session && typeof session.companyId === 'string' ? session.companyId : null
  return { id: session.id, companyId }
}
