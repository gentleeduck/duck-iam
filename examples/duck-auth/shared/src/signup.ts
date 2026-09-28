import { AuthError } from '@gentleduck/auth/core'
import { type AppAuth, PAGES } from './auth'
import { readString } from './body'

/** One `@` with something either side; the emailed link is what proves the address. */
const EMAIL = /^[^\s@]+@[^\s@]+$/

/** A password account, unverified until its emailed link is opened. One function, so every backend signs up alike. */
export async function signUp(auth: AppAuth, body: unknown): Promise<{ identityId: string }> {
  const email = readString(body, 'email')?.trim() ?? ''
  const name = readString(body, 'name')?.trim() ?? ''
  const password = readString(body, 'password') ?? ''
  if (!EMAIL.test(email) || email.length > 254 || name.length === 0 || name.length > 100) {
    throw new AuthError('AUTH_INVALID_PARAMETERS')
  }
  auth.passwords.assertStrength(password)

  const identity = await auth.identities.create({ profile: { email, name, username: email } })
  try {
    await auth.passwords.set(identity.id, password, auth.cfg.stores.credentials)
  } catch (err) {
    // Nothing holds the new identity yet: it goes, so the address can sign up again.
    await auth.identities.erase(identity.id, { reason: 'sign-up rolled back' }).catch(() => {})
    throw err
  }
  await auth.flows.requestEmailVerification({ identityId: identity.id, callbackPath: PAGES.verifyEmail })
  return { identityId: identity.id }
}
