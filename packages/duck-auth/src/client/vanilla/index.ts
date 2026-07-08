/**
 * Vanilla client — the framework-free auth client. `authCreateClient` builds a
 * fetch-based client with a session pub/sub store; every method resolves to the
 * `Envelope` envelope. Types live in `./types`.
 */
import type { Identity } from '~/core'
import type { Envelope } from '~/core/types/session'
import type { VanillaClient } from './types'

export type { VanillaClient } from './types'

export function createAuthClient<Profile extends Identity.ProfileMetadataBase>(
  cfg: VanillaClient.Config = {},
): VanillaClient.Client<Profile> {
  const baseUrl = (cfg.baseUrl ?? '/auth').replace(/\/$/, '')
  const fetchImpl: typeof globalThis.fetch = cfg.fetch ?? (globalThis.fetch as typeof globalThis.fetch)
  if (!fetchImpl) {
    throw new Error('@gentleduck/AUTH/client/vanilla: no fetch available - pass `fetch` via config')
  }
  const headers = { 'content-type': 'application/json', ...(cfg.headers ?? {}) }
  const observers = new Set<(state: VanillaClient.SessionResult<Profile>) => void>()
  let lastState: VanillaClient.SessionResult<Profile> = { session: null, identity: null }

  function notify(state: VanillaClient.SessionResult<Profile>): void {
    lastState = state
    for (const fn of observers) {
      try {
        fn(state)
      } catch (err) {
        console.error('[@gentleduck/AUTH/client/vanilla] observer threw:', err)
      }
    }
  }

  /**
   * Perform a request and always resolve to an {@link Envelope}. The server
   * is expected to speak the envelope; if it doesn't (or the network fails) we
   * synthesize one so callers never have to branch on transport details.
   */
  async function call(method: string, path: string, body?: unknown): Promise<Envelope<unknown, string>> {
    let res: Response
    try {
      res = await fetchImpl(`${baseUrl}${path}`, {
        method,
        headers,
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
      // Best-effort: clear local session regardless of transport outcome.
      notify({ session: null, identity: null })
      return (res.ok ? res : { ok: true, code: 'AUTH_SIGNOUT_OK', data: {} }) as Envelope<Record<string, never>, string>
    },
    async getSession() {
      const res = (await call('GET', '/session')) as Envelope<VanillaClient.SessionResult<Profile>, string>
      notify(res.ok && res.data ? res.data : { session: null, identity: null })
      return res
    },
    async beginProvider(id, input) {
      return call('POST', `/providers/${encodeURIComponent(id)}/begin`, input ?? {})
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
