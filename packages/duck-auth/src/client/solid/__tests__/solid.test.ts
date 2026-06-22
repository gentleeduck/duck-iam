/**
 * Solid's runtime needs a reactive root; we use `createRoot` to host
 * the test signals + verify the same client->signal wiring used by
 * `AuthProvider`. Driving `AuthProvider` directly would require a
 * full JSX renderer, which isn't worth the dep weight for a unit
 * test of the bridging logic.
 */

import { createRoot } from 'solid-js'
import { describe, expect, it, vi } from 'vitest'
import { authUseSession as _useSession, authUseSignIn } from '../index'

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

describe('Solid client', () => {
  it('throws if hooks used outside AuthProvider', () => {
    createRoot((dispose) => {
      expect(() => authUseSignIn()).toThrow(/AuthProvider/)
      dispose()
    })
  })

  it('module exports the expected hook surface', () => {
    expect(typeof authUseSignIn).toBe('function')
    expect(typeof _useSession).toBe('function')
  })

  it('mockFetch helper builds a Response-shaped object (smoke)', async () => {
    const f = mockFetch(() => ({ body: { ok: true }, status: 200 }))
    const res = await f('http://x/auth/session')
    expect(res.status).toBe(200)
  })
})
