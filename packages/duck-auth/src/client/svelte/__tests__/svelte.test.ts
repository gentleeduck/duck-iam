import { describe, expect, it, vi } from 'vitest'
import { createAuthStore } from '../index'

function mockFetch(handler: (path: string) => { status: number; body: unknown }) {
  return vi.fn(async (url: string) => {
    const path = new URL(url, 'http://x').pathname
    const { status, body } = handler(path)
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => (body === null || body === undefined ? '' : JSON.stringify(body)),
    } as unknown as Response
  })
}

describe('createAuthStore (Svelte)', () => {
  it('subscribes synchronously with the initial state, then updates on signIn', async () => {
    const fetchImpl = mockFetch((path) => {
      if (path === '/auth/signin') return { body: { ok: true }, status: 200 }
      if (path === '/auth/session') return { body: { identity: { id: 'i1' }, session: { id: 's1' } }, status: 200 }
      return { body: null, status: 404 }
    })
    const store = createAuthStore({ baseUrl: '/auth', fetch: fetchImpl as never, noInitialFetch: true })
    const seen: string[] = []
    const unsub = store.state.subscribe((s) => seen.push(s.status))
    expect(seen[0]).toBe('guest')
    await store.signIn({ input: { email: 'a@x', password: 'x' }, providerId: 'password' })
    expect(seen[seen.length - 1]).toBe('authed')
    unsub()
  })

  it('refresh() pulls /session and notifies subscribers', async () => {
    const fetchImpl = mockFetch((path) =>
      path === '/auth/session'
        ? { body: { identity: { id: 'i2' }, session: { id: 's2' } }, status: 200 }
        : { body: null, status: 404 },
    )
    const store = createAuthStore({ baseUrl: '/auth', fetch: fetchImpl as never, noInitialFetch: true })
    await store.refresh()
    let observed: string = ''
    store.state.subscribe((s) => {
      observed = s.status
    })()
    expect(observed).toBe('authed')
  })

  it('unsubscribe stops notifications', async () => {
    const fetchImpl = mockFetch(() => ({ body: { identity: null, session: null }, status: 200 }))
    const store = createAuthStore({ baseUrl: '/auth', fetch: fetchImpl as never, noInitialFetch: true })
    let count = 0
    const off = store.state.subscribe(() => {
      count++
    })
    off()
    await store.refresh()
    expect(count).toBe(1)
  })
})
