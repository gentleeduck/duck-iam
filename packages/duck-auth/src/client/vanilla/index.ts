/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Identity } from '../../core/types/identity'
import type { Session } from '../../core/types/session'

/**
 * Framework-free client SDK. Drives the mounted server routes via `fetch`
 * (or a configurable transport). Returns plain typed values; consumers
 * wrap into React/Vue/Svelte/Solid state in their own client packages.
 *
 * Generics flow: `createAuthClient<MyProfile>()` types `signIn`/`session`
 * return values with the consumer's profile shape so `session.identity.profile.email`
 * autocompletes end-to-end.
 */

export interface AuthClientConfig {
  /** Mount point on the server. Default `/auth`. */
  baseUrl?: string
  /** Override the fetch impl (test stubs, retry wrappers, etc.). */
  fetch?: typeof globalThis.fetch
  /** Override how subscribed observers are notified. Default: synchronous. */
  notifyImmediately?: boolean
  /** Optional headers to merge into every request (e.g. tenant header). */
  headers?: Record<string, string>
}

export interface SignInOptions {
  providerId: string
  input: unknown
  /** Override the route path under baseUrl. Default `/signin`. */
  path?: string
}

export interface SignInResult<Profile = unknown> {
  ok: boolean
  session: Session.ISession | null
  identity: Identity.IIdentity<Profile> | null
  /** Echo of the route response body for non-session intents (json results). */
  body?: unknown
}

export interface SessionResult<Profile = unknown> {
  session: Session.ISession | null
  identity: Identity.IIdentity<Profile> | null
}

export interface AuthClient<Profile = unknown> {
  /** POST /auth/signin */
  signIn(opts: SignInOptions): Promise<SignInResult<Profile>>
  /** POST /auth/signout */
  signOut(): Promise<{ ok: true }>
  /** GET /auth/session */
  getSession(): Promise<SessionResult<Profile>>
  /** POST /auth/providers/:id/begin */
  beginProvider(id: string, input?: unknown): Promise<{ body: unknown }>
  /** Observe session changes. Returned function unsubscribes. */
  onChange(handler: (state: SessionResult<Profile>) => void): () => void
  /** Force a session refetch + notify observers. */
  refresh(): Promise<SessionResult<Profile>>
}

export function createAuthClient<Profile = unknown>(cfg: AuthClientConfig = {}): AuthClient<Profile> {
  const baseUrl = (cfg.baseUrl ?? '/auth').replace(/\/$/, '')
  const fetchImpl: typeof globalThis.fetch = cfg.fetch ?? (globalThis.fetch as typeof globalThis.fetch)
  if (!fetchImpl) {
    throw new Error('@gentleduck/auth/client/vanilla: no fetch available - pass `fetch` via config')
  }
  const headers = { 'content-type': 'application/json', ...(cfg.headers ?? {}) }
  const observers = new Set<(state: SessionResult<Profile>) => void>()
  let lastState: SessionResult<Profile> = { session: null, identity: null }

  function notify(state: SessionResult<Profile>): void {
    lastState = state
    for (const fn of observers) {
      try {
        fn(state)
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error('[@gentleduck/auth/client/vanilla] observer threw:', err)
      }
    }
  }

  async function call(method: string, path: string, body?: unknown): Promise<{ status: number; body: unknown }> {
    const res = await fetchImpl(`${baseUrl}${path}`, {
      method,
      headers,
      credentials: 'include',
      ...(body !== undefined && { body: JSON.stringify(body) }),
    })
    const text = await res.text()
    let parsed: unknown = null
    if (text) {
      try {
        parsed = JSON.parse(text)
      } catch {
        parsed = text
      }
    }
    return { status: res.status, body: parsed }
  }

  return {
    async signIn(opts) {
      const path = opts.path ?? '/signin'
      const { status, body } = await call('POST', path, {
        providerId: opts.providerId,
        input: opts.input,
      })
      if (status < 200 || status >= 300) {
        return { ok: false, session: null, identity: null, body }
      }
      // After a successful signin, the server has set the cookie; refresh state.
      const state = await this.refresh()
      return { ok: true, session: state.session, identity: state.identity, body }
    },
    async signOut() {
      await call('POST', '/signout').catch(() => {})
      notify({ session: null, identity: null })
      return { ok: true }
    },
    async getSession() {
      const { body } = await call('GET', '/session')
      const state = body as SessionResult<Profile>
      notify(state)
      return state
    },
    async beginProvider(id, input) {
      const { body } = await call('POST', `/providers/${encodeURIComponent(id)}/begin`, input ?? {})
      return { body }
    },
    onChange(handler) {
      observers.add(handler)
      if (cfg.notifyImmediately !== false) handler(lastState)
      return () => observers.delete(handler)
    },
    async refresh() {
      return this.getSession()
    },
  }
}
