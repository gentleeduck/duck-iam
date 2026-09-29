import { AuthError, type Provider } from '@gentleduck/auth/core'
import { isSafeRedirectUrl } from '@gentleduck/auth/server/generic'
import { APP_URL, type AppAuth, PAGES } from './auth'
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

/** Starts a provider. A script cannot follow the redirect to the IdP, so it gets `{ url }` to navigate to. */
export async function beginProvider(auth: AppAuth, id: string, body: unknown): Promise<Provider.Intent[]> {
  const intents = await auth.flows.beginProvider(id, body ?? {})
  return intents.map((i) =>
    i.type === 'redirect' && isSafeRedirectUrl(i.url) ? { body: { url: i.url }, status: 200, type: 'json' } : i,
  )
}

/**
 * Where the IdP returns the browser: `params` is the query on a redirect, the form on Apple's post. Never
 * CSRF-guarded, since that post is cross-site by design and the signed state is the proof. The browser lands
 * on the app once signed in, and on the sign-in page with the code otherwise.
 */
export async function providerCallback(
  auth: AppAuth,
  id: string,
  params: URLSearchParams,
  headers: Headers,
  caller: Caller,
): Promise<Provider.Intent[]> {
  const failedWith = (code: string): Provider.Intent[] => [
    { type: 'redirect', url: `${APP_URL}${PAGES.signIn}?error=${code}` },
  ]
  if (!auth.providers.has(id) || auth.providers.get(id).kind !== 'oauth') return failedWith('AUTH_PROVIDER_FAILED')
  const user = params.get('user')
  try {
    const { intents } = await auth.flows.signIn({
      input: {
        code: params.get('code') ?? '',
        cookieHeader: headers.get('cookie') ?? '',
        state: params.get('state') ?? '',
        ...(user !== null && { user }),
      },
      providerId: id,
      ...caller,
      previousSid: auth.transport.extract({ headers }) ?? undefined,
    })
    const failed = intents.find((intent) => intent.type === 'error')
    if (failed) return [...intents.filter((intent) => intent.type !== 'error'), ...failedWith(failed.code)]
    return [...intents, { type: 'redirect', url: APP_URL }]
  } catch (err) {
    if (!(err instanceof AuthError)) throw err
    return failedWith(err.code)
  }
}
