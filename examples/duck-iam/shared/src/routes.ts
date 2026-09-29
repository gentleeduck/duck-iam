import { AuthError, type Provider } from '@gentleduck/auth/core'
import type { AppAuth } from './auth'
import { readString } from './body'

/** What a backend's caller helper read: the address its framework resolved, and the user agent. */
type Caller = { ip?: string; userAgent?: string }

/** A `{ providerId, input }` sign-in. Rotates any session the browser already holds. */
export async function signIn(
  auth: AppAuth,
  headers: Headers,
  body: unknown,
  caller: Caller,
): Promise<Provider.Intent[]> {
  const providerId = readString(body, 'providerId')
  if (!providerId) throw new AuthError('AUTH_INVALID_PARAMETERS')
  const input: unknown = typeof body === 'object' && body !== null ? Reflect.get(body, 'input') : undefined
  const { intents } = await auth.flows.signIn({
    input: input ?? {},
    providerId,
    ...caller,
    previousSid: auth.transport.extract({ headers }) ?? undefined,
  })
  return intents
}

/** Revokes the session and clears its cookies; a caller holding none still gets them cleared. */
export async function signOut(auth: AppAuth, headers: Headers): Promise<Provider.Intent[]> {
  const sid = auth.transport.extract({ headers })
  return sid ? (await auth.flows.signOut(sid)).intents : auth.transport.revoke()
}

/** The caller's session and identity. `csrfHash` is server-side state; the browser holds the plaintext. */
export async function currentSession(auth: AppAuth, headers: Headers) {
  const resolved = await auth.resolveSession({ headers }).orNull()
  if (!resolved) return { session: null, identity: null }
  const { csrfHash: _csrfHash, ...session } = resolved.session
  return { session, identity: resolved.identity }
}
