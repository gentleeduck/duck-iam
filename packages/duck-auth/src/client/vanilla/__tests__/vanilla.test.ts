import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { browserOverEngine, type Profile } from '~/test/browser-over-engine'
import { createAuthClient } from '../index'

afterEach(() => vi.unstubAllGlobals())

function mockFetch(handler: (path: string, init: RequestInit) => { status: number; body: unknown }) {
  return vi.fn(async (url: RequestInfo | URL, init: RequestInit = {}) => {
    const { status, body } = handler(new URL(String(url), 'http://x').pathname, init)
    return new Response(body === null || body === undefined ? null : JSON.stringify(body), { status })
  })
}

describe('createAuthClient', () => {
  describe('signIn', () => {
    it('happy path: POSTs /signin then refreshes /session', async () => {
      const calls: string[] = []
      const fetchImpl = mockFetch((path) => {
        calls.push(path)
        if (path === '/auth/signin') return { status: 200, body: { ok: true, code: 'AUTH_SIGNIN_OK', data: {} } }
        if (path === '/auth/session')
          return {
            status: 200,
            body: { ok: true, code: 'AUTH_SESSION_OK', data: { session: { id: 's1' }, identity: { id: 'i1' } } },
          }
        return { status: 404, body: null }
      })
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl })
      const result = await client.signIn({ providerId: 'password', input: { email: 'a@x', password: 'x' } })
      expect(result.ok).toBe(true)
      if (!result.ok) throw new Error('expected ok')
      expect(result.data.identity?.id).toBe('i1')
      expect(calls).toEqual(['/auth/signin', '/auth/session'])
    })

    it('non-2xx returns ok:false without refresh', async () => {
      const fetchImpl = mockFetch((path) => {
        if (path === '/auth/signin')
          return { status: 401, body: { ok: false, error: { code: 'AUTH_INVALID_CREDENTIALS' } } }
        return { status: 200, body: { ok: true, code: 'AUTH_SESSION_OK', data: { session: null, identity: null } } }
      })
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl })
      const result = await client.signIn({ providerId: 'password', input: {} })
      expect(result.ok).toBe(false)
      if (result.ok) throw new Error('expected error')
      expect(result.error.code).toBe('AUTH_INVALID_CREDENTIALS')
    })
  })

  describe('signOut', () => {
    it('POSTs /signout and notifies observers with null state', async () => {
      const fetchImpl = mockFetch(() => ({ status: 200, body: { ok: true } }))
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl, notifyImmediately: false })
      const onChange = vi.fn()
      client.onChange(onChange)
      await client.signOut()
      expect(onChange).toHaveBeenCalledWith({ session: null, identity: null })
    })

    it('a refused signout still clears local state, and says the server refused', async () => {
      const fetchImpl = mockFetch(() => ({ status: 500, body: { ok: false, error: { code: 'AUTH_INTERNAL' } } }))
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl, notifyImmediately: false })
      const onChange = vi.fn()
      client.onChange(onChange)

      const result = await client.signOut()

      // The session is still live on the server, so reporting success would tell the caller the one
      // thing signout exists to guarantee, wrongly.
      expect(result.ok).toBe(false)
      if (result.ok) throw new Error('expected the refusal to surface')
      expect(result.error.code).toBe('AUTH_INTERNAL')
      expect(onChange).toHaveBeenCalledWith({ session: null, identity: null })
    })

    it('an unreachable server surfaces the network error rather than a clean signout', async () => {
      const fetchImpl = vi.fn(async () => {
        throw new Error('offline')
      })
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl, notifyImmediately: false })
      const onChange = vi.fn()
      client.onChange(onChange)

      const result = await client.signOut()

      expect(result.ok).toBe(false)
      if (result.ok) throw new Error('expected the network error to surface')
      expect(result.error.code).toBe('AUTH_NETWORK_ERROR')
      expect(onChange).toHaveBeenCalledWith({ session: null, identity: null })
    })
  })

  describe('getSession', () => {
    it('returns the parsed session response', async () => {
      const fetchImpl = mockFetch(() => ({
        status: 200,
        body: { ok: true, code: 'AUTH_SESSION_OK', data: { session: { id: 's' }, identity: { id: 'i' } } },
      }))
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl })
      const r = await client.getSession()
      if (!r.ok) throw new Error('expected ok')
      expect(r.data.identity?.id).toBe('i')
    })

    it('a body cut off mid-read resolves to the network-error envelope, not a rejection', async () => {
      const cut = new ReadableStream({
        start(controller) {
          controller.error(new TypeError('terminated'))
        },
      })
      const client = createAuthClient({ fetch: async () => new Response(cut) })
      expect(await client.getSession()).toMatchObject({ error: { code: 'AUTH_NETWORK_ERROR' }, ok: false })
    })
  })

  describe('destructured', () => {
    it('signs in and refreshes against a real engine without leaning on `this`', async () => {
      const { fetch, id } = await browserOverEngine()
      const { refresh, signIn } = createAuthClient<Profile>({ csrfCookieName: 'duck-csrf', fetch })

      const signedIn = await signIn({ input: { email: 'a@x.com', password: 'correct-pw' }, providerId: 'password' })
      expect(signedIn.ok && signedIn.data.identity?.id).toBe(id)
      const refreshed = await refresh()
      expect(refreshed.ok && refreshed.data.identity?.id).toBe(id)
    })
  })

  describe('beginProvider', () => {
    it('POSTs to /providers/:id/begin and returns body', async () => {
      let captured = ''
      const fetchImpl = mockFetch((path, init) => {
        captured = path
        const body = typeof init.body === 'string' ? JSON.parse(init.body) : null
        return { status: 200, body: { ok: true, code: 'AUTH_BEGIN_OK', data: { echoed: body } } }
      })
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl })
      const r = await client.beginProvider('magic-link', { email: 'a@x.com' })
      expect(captured).toBe('/auth/providers/magic-link/begin')
      if (!r.ok) throw new Error('expected ok')
      expect(r.data).toEqual({ echoed: { email: 'a@x.com' } })
    })

    it('URL-encodes provider ids that contain unsafe chars', async () => {
      let captured = ''
      const fetchImpl = mockFetch((path) => {
        captured = path
        return { status: 200, body: null }
      })
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl })
      await client.beginProvider('oauth:google')
      expect(captured).toBe('/auth/providers/oauth%3Agoogle/begin')
    })

    it('sends the page to the IdP, holding the cookie the callback is bound to', async () => {
      const { fetch } = await browserOverEngine()
      const assign = vi.fn()
      vi.stubGlobal('location', { assign })
      const res = await createAuthClient<Profile>({ csrfCookieName: 'duck-csrf', fetch }).beginProvider('oauth:google')
      expect(res.ok).toBe(true)
      expect(assign).toHaveBeenCalledWith(
        expect.stringMatching(/^https:\/\/accounts\.google\.com\/o\/oauth2\/v2\/auth\?/),
      )
      expect(document.cookie).toMatch(/(^|; )duck-oauth=/)
    })

    it('stays on the page for a flow that answers with a body', async () => {
      const assign = vi.fn()
      vi.stubGlobal('location', { assign })
      const fetchImpl = mockFetch(() => ({ status: 200, body: { challenge: 'c' } }))
      await createAuthClient({ fetch: fetchImpl }).beginProvider('passkey')
      expect(assign).not.toHaveBeenCalled()
    })
  })

  describe('onChange', () => {
    it('replays the state on subscribe, but only once there is one to replay', async () => {
      const fetchImpl = mockFetch(() => ({ status: 200, body: null }))
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl })
      // Before the first read the client holds nothing. It used to replay an empty state here, which
      // every framework binding reads as `status: 'guest'` - signed out, announced before asking.
      const early = vi.fn()
      client.onChange(early)
      expect(early).not.toHaveBeenCalled()

      await client.getSession()
      const late = vi.fn()
      client.onChange(late)
      expect(late).toHaveBeenCalledWith({ session: null, identity: null })
    })

    it('handler errors are caught (do not break subsequent notifications)', async () => {
      const fetchImpl = mockFetch(() => ({ status: 200, body: { session: null, identity: null } }))
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl, notifyImmediately: false })
      const goodHandler = vi.fn()
      client.onChange(() => {
        throw new Error('boom')
      })
      client.onChange(goodHandler)
      await client.refresh()
      expect(goodHandler).toHaveBeenCalled()
    })

    it('unsubscribe stops further notifications', async () => {
      const fetchImpl = mockFetch(() => ({ status: 200, body: { session: null, identity: null } }))
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl, notifyImmediately: false })
      const handler = vi.fn()
      const unsubscribe = client.onChange(handler)
      unsubscribe()
      await client.refresh()
      expect(handler).not.toHaveBeenCalled()
    })
  })
  describe('content-type', () => {
    it('labels a request JSON only when it carries a body', async () => {
      const labels: string[] = []
      const fetchImpl = mockFetch((path, init) => {
        labels.push(`${init.method} ${path} ${new Headers(init.headers).get('content-type')}`)
        return { status: 200, body: null }
      })
      const client = createAuthClient({ fetch: fetchImpl })
      await client.getSession()
      await client.signOut()
      await client.signUp({ email: 'a@x.com' })
      expect(labels).toEqual([
        'GET /auth/session null',
        'POST /auth/signout null',
        'POST /auth/signup application/json',
      ])
    })
  })

  describe('csrf', () => {
    // The suite runs in node, where there is no document to read a cookie from.
    function withCookie(cookie: string) {
      vi.stubGlobal('document', { cookie })
    }

    it('echoes the csrf cookie on unsafe methods', async () => {
      withCookie('other=1; __Host-duck-csrf=tok123; more=2')
      const fetchImpl = mockFetch(() => ({ status: 200, body: { ok: true, code: 'AUTH_SIGNOUT_OK', data: {} } }))
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl })

      await client.signOut()

      const headers = new Headers(fetchImpl.mock.calls[0]?.[1]?.headers)
      expect(headers.get('x-csrf-token')).toBe('tok123')
    })

    it('sends no token on safe methods', async () => {
      withCookie('__Host-duck-csrf=tok123')
      const fetchImpl = mockFetch(() => ({ status: 200, body: { session: null, identity: null } }))
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl })

      await client.getSession()

      const headers = new Headers(fetchImpl.mock.calls[0]?.[1]?.headers)
      expect(headers.get('x-csrf-token')).toBeNull()
    })

    it('omits the header when the cookie is absent', async () => {
      withCookie('unrelated=1')
      const fetchImpl = mockFetch(() => ({ status: 200, body: { ok: true, code: 'AUTH_SIGNOUT_OK', data: {} } }))
      const client = createAuthClient({ baseUrl: '/auth', fetch: fetchImpl })

      await client.signOut()

      const headers = new Headers(fetchImpl.mock.calls[0]?.[1]?.headers)
      expect(headers.get('x-csrf-token')).toBeNull()
    })

    it('honours configured cookie and header names', async () => {
      withCookie('csrf=abc')
      const fetchImpl = mockFetch(() => ({ status: 200, body: { ok: true, code: 'AUTH_SIGNOUT_OK', data: {} } }))
      const client = createAuthClient({
        baseUrl: '/auth',
        csrfCookieName: 'csrf',
        csrfHeaderName: 'x-token',
        fetch: fetchImpl,
      })

      await client.signOut()

      const headers = new Headers(fetchImpl.mock.calls[0]?.[1]?.headers)
      expect(headers.get('x-token')).toBe('abc')
    })
  })
})
