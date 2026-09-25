/**
 * Vanilla client: the framework-free auth client. `createAuthClient` builds a
 * fetch-based client with a session pub/sub store; every method resolves to the
 * `Envelope` envelope. Types live in `./types`.
 */

import { AuthError } from '~/core/errors'
import type { Envelope } from '~/core/errors/errors.types'
import type { Identities } from '~/core/identities'
import { reviveSessionResult } from './revive'
import type { VanillaClient } from './types'

/**
 * The wire-to-row converters. `VanillaClient.Serialized<T>` maps `Date -> string`
 * to describe what `JSON.stringify` actually put on the wire, and these are the
 * only things that produce the row type from it, so an app calling `/session`
 * with its own fetch reaches the same `Date`s the client hands back.
 */
export { reviveIdentity, reviveSession, reviveSessionResult } from './revive'
export type { VanillaClient } from './types'

/** Mirrors SAFE_METHODS in core/csrf. */
const CSRF_SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE'])

/** Framework-free auth client. Every framework client wraps this one. */
export function createAuthClient<Profile extends Identities.ProfileMetadataBase>(
  cfg: VanillaClient.Cfg = {},
): VanillaClient.Client<Profile> {
  const baseUrl = (cfg.baseUrl ?? '/auth').replace(/\/$/, '')
  const fetchImpl: typeof globalThis.fetch = cfg.fetch ?? (globalThis.fetch as typeof globalThis.fetch)
  if (!fetchImpl) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: '@gentleduck/auth/client/vanilla: no fetch available - pass `fetch` via config',
    })
  }
  const headers = { 'content-type': 'application/json', ...(cfg.headers ?? {}) }
  const observers = new Set<(state: VanillaClient.SessionResult<Profile>) => void>()
  // `null` until something has actually been read; see `onChange`.
  let lastState: VanillaClient.SessionResult<Profile> | null = null

  function notify(state: VanillaClient.SessionResult<Profile>): void {
    lastState = state
    for (const fn of observers) {
      try {
        fn(state)
      } catch (err) {
        console.error('[@gentleduck/auth/client/vanilla] observer threw:', err)
      }
    }
  }

  /** Without this every cookie-authenticated write fails `verifyCsrf`, signout included. */
  function csrfHeader(method: string): Record<string, string> {
    if (CSRF_SAFE_METHODS.has(method.toUpperCase())) return {}
    if (typeof document === 'undefined') return {}

    const name = cfg.csrfCookieName ?? '__Host-duck-csrf'
    const match = document.cookie.split('; ').find((entry) => entry.startsWith(`${name}=`))
    if (!match) return {}

    return { [cfg.csrfHeaderName ?? 'x-csrf-token']: decodeURIComponent(match.slice(name.length + 1)) }
  }

  /**
   * Always resolves to an {@link Envelope}. The server is expected to speak it; when it does not, or
   * the network fails, one is synthesised so callers never branch on transport details.
   */
  async function call(method: string, path: string, body?: unknown): Promise<Envelope<unknown, string>> {
    let res: Response
    try {
      res = await fetchImpl(`${baseUrl}${path}`, {
        method,
        headers: { ...headers, ...csrfHeader(method) },
        credentials: 'include',
        ...(body !== undefined && { body: JSON.stringify(body) }),
      })
    } catch (cause) {
      return { ok: false, error: { code: 'AUTH_NETWORK_ERROR', cause } }
    }

    const text = await res.text()
    let parsed: unknown = null
    if (text) {
      try {
        parsed = JSON.parse(text)
      } catch {
        parsed = text
      }
    }

    // Server already returned the envelope → pass it through untouched.
    if (parsed && typeof parsed === 'object' && 'ok' in (parsed as Record<string, unknown>)) {
      return parsed as Envelope<unknown, string>
    }

    // Non-enveloped server → wrap the raw body based on HTTP status.
    return res.ok
      ? { ok: true, code: 'AUTH_OK', data: parsed }
      : { ok: false, error: { code: 'AUTH_HTTP_ERROR', cause: parsed } }
  }

  return {
    async signIn(opts) {
      const res = await call('POST', opts.path ?? '/signin', { providerId: opts.providerId, input: opts.input })
      // Signin itself returns no session payload; on success the cookie is set,
      // so hydrate + return the session envelope. On failure, surface it as-is.
      return res.ok ? this.getSession() : res
    },
    async signUp(input, opts) {
      return call('POST', opts?.path ?? '/signup', input ?? {})
    },
    async signOut() {
      const res = await call('POST', '/signout')
      // The local state clears either way: the caller asked to sign out, and a cached session that
      // outlives the request is worse than none. The envelope still reports what the server did,
      // because a refused signout leaves the session live on the server and only the caller can
      // decide whether to retry or to say so.
      notify({ session: null, identity: null })
      return res
    },
    async getSession() {
      // Typed as what the wire carries, not what callers are owed: asserting the row type here
      // would hide a missing revival from `tsc`. `| null` because `call` synthesises `data:
      // parsed`, and an empty 200 parses to `null`.
      const raw = (await call('GET', '/session')) as Envelope<
        VanillaClient.SerializedSessionResult<Profile> | null,
        string
      >
      const res: Envelope<VanillaClient.SessionResult<Profile>, string> = raw.ok
        ? { ...raw, data: reviveSessionResult(raw.data ?? { identity: null, session: null }) }
        : raw
      notify(res.ok ? res.data : { session: null, identity: null })
      return res
    },
    async beginProvider(id, input) {
      return call('POST', `/providers/${encodeURIComponent(id)}/begin`, input ?? {})
    },
    onChange(handler) {
      observers.add(handler)
      // Only a state the client actually holds. This used to replay an empty one before any fetch had
      // happened, and all four framework bindings read "no identity" as `status: 'guest'` - so a signed-in
      // user was reported signed out on subscribe, and the `'loading'` status those bindings declare could
      // never be observed at all. An app gating on it flashed, or redirected to, its sign-in screen on
      // every load. A signed-out state that was actually read is a state, and is still replayed.
      if (cfg.notifyImmediately !== false && lastState) handler(lastState)
      return () => observers.delete(handler)
    },
    async refresh() {
      return this.getSession()
    },
  }
}
