import { beforeEach, describe, expect, it, vi } from 'vitest'
import { authCreateClient } from '../index'

function mockFetch(handler: (path: string, init: RequestInit) => { status: number; body: unknown }) {
  return vi.fn(async (url: string, init: RequestInit = {}) => {
    const path = new URL(url, 'http://x').pathname
    const { status, body } = handler(path, init)
    return {
      status,
      ok: status >= 200 && status < 300,
      text: async () => (body === null || body === undefined ? '' : JSON.stringify(body)),
    } as unknown as Response
  })
}

describe('authCreateClient', () => {
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
      const client = authCreateClient({ baseUrl: '/auth', fetch: fetchImpl as never })
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
      const client = authCreateClient({ baseUrl: '/auth', fetch: fetchImpl as never })
      const result = await client.signIn({ providerId: 'password', input: {} })
      expect(result.ok).toBe(false)
      if (result.ok) throw new Error('expected error')
      expect(result.error.code).toBe('AUTH_INVALID_CREDENTIALS')
    })
  })

  describe('signOut', () => {
    it('POSTs /signout and notifies observers with null state', async () => {
      const fetchImpl = mockFetch(() => ({ status: 200, body: { ok: true } }))
      const client = authCreateClient({ baseUrl: '/auth', fetch: fetchImpl as never, notifyImmediately: false })
      const onChange = vi.fn()
      client.onChange(onChange)
      await client.signOut()
      expect(onChange).toHaveBeenCalledWith({ session: null, identity: null })
    })
  })

  describe('getSession', () => {
    it('returns the parsed session response', async () => {
      const fetchImpl = mockFetch(() => ({
        status: 200,
        body: { ok: true, code: 'AUTH_SESSION_OK', data: { session: { id: 's' }, identity: { id: 'i' } } },
      }))
      const client = authCreateClient({ baseUrl: '/auth', fetch: fetchImpl as never })
      const r = await client.getSession()
      if (!r.ok) throw new Error('expected ok')
      expect(r.data.identity?.id).toBe('i')
    })
  })

  describe('beginProvider', () => {
    it('POSTs to /providers/:id/begin and returns body', async () => {
      let captured = ''
      const fetchImpl = mockFetch((path, init) => {
        captured = path
        const body = init.body ? JSON.parse(init.body as string) : null
        return { status: 200, body: { ok: true, code: 'AUTH_BEGIN_OK', data: { echoed: body } } }
      })
      const client = authCreateClient({ baseUrl: '/auth', fetch: fetchImpl as never })
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
      const client = authCreateClient({ baseUrl: '/auth', fetch: fetchImpl as never })
      await client.beginProvider('oauth:google')
      expect(captured).toBe('/auth/providers/oauth%3Agoogle/begin')
    })
  })

  describe('onChange', () => {
    it('synchronously fires the handler on subscribe by default', () => {
      const fetchImpl = mockFetch(() => ({ status: 200, body: null }))
      const client = authCreateClient({ baseUrl: '/auth', fetch: fetchImpl as never })
      const handler = vi.fn()
      client.onChange(handler)
      expect(handler).toHaveBeenCalledWith({ session: null, identity: null })
    })

    it('handler errors are caught (do not break subsequent notifications)', async () => {
      const fetchImpl = mockFetch(() => ({ status: 200, body: { session: null, identity: null } }))
      const client = authCreateClient({ baseUrl: '/auth', fetch: fetchImpl as never, notifyImmediately: false })
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
      const client = authCreateClient({ baseUrl: '/auth', fetch: fetchImpl as never, notifyImmediately: false })
      const handler = vi.fn()
      const unsubscribe = client.onChange(handler)
      unsubscribe()
      await client.refresh()
      expect(handler).not.toHaveBeenCalled()
    })
  })
})
