import { randomUUID } from 'node:crypto'
import { AuthError } from '@gentleduck/auth/core'
import type { AppAuth } from './auth'
import { readEmail, readString, readTrimmedString } from './body'
import type { AppDb } from './iam'
import { companies, users } from './schema'

export interface SignUpResult {
  identityId: string
  companyId: string
}

// A signup creates its own company and becomes its admin — DuckMarket is multi-tenant, so a
// brand-new identity needs somewhere to belong. One shared function so all four frameworks get
// the same transaction/rollback shape instead of four copies that could drift.
export async function signUp(
  auth: AppAuth,
  db: AppDb,
  assignAdmin: (identityId: string, companyId: string) => Promise<void>,
  body: unknown,
): Promise<SignUpResult> {
  const email = readEmail(body, 'email')
  const password = readString(body, 'password')
  const name = readTrimmedString(body, 'name')
  const companyName = readTrimmedString(body, 'companyName')
  if (!email || !password || !name || !companyName) throw new AuthError('AUTH_INVALID_PARAMETERS')
  auth.passwords.assertStrength(password)

  const identity = await auth.identities.create({ profile: { email, name, username: email } })
  const companyId = randomUUID()
  try {
    await auth.passwords.set(identity.id, password, auth.cfg.stores.credentials)
    // One db transaction: a company row can't exist without its user row, or vice versa.
    await db.transaction(async (tx) => {
      await tx.insert(companies).values({ id: companyId, name: companyName })
      await tx.insert(users).values({ id: identity.id, email, name, companyId })
    })
  } catch (err) {
    // Nothing durable depends on this identity yet — erase it so the email is free to retry.
    await auth.identities
      .erase(identity.id, { reason: 'signup rollback: setup failed before the account existed' })
      .catch(() => {})
    throw err
  }

  // The account is durable now; a role-assignment failure here is left as-is rather than rolled
  // back (erasing would violate users.id's foreign key into the identity).
  await assignAdmin(identity.id, companyId)
  return { identityId: identity.id, companyId }
}
