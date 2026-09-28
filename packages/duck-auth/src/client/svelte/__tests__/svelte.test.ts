import { afterEach, describe, expect, it, vi } from 'vitest'
import { browserOverEngine, type Profile } from '~/test/browser-over-engine'
import { createAuthStore } from '../index'
import type { SvelteClient } from '../types'

afterEach(() => {
  vi.unstubAllGlobals()
})

const credentials = { input: { email: 'a@x.com', password: 'correct-pw' }, providerId: 'password' }

describe('the Svelte store', () => {
  it('signs in and out through a real engine, and the store follows', async () => {
    const { adapter, fetch, id } = await browserOverEngine()
    const store = createAuthStore<Profile>({ csrfCookieName: 'duck-csrf', fetch })
    const seen: SvelteClient.State<Profile>[] = []
    store.state.subscribe((state) => seen.push(state))
    await vi.waitFor(() => expect(seen.at(-1)?.status).toBe('guest'))

    expect((await store.signIn(credentials)).ok).toBe(true)
    expect(seen.at(-1)?.identity?.id).toBe(id)
    expect(seen.at(-1)?.identity?.createdAt).toBeInstanceOf(Date)

    expect((await store.signOut()).ok).toBe(true)
    expect(await adapter.sessions.listByIdentity(id)).toEqual([])
    expect(seen.map((state) => state.status)).toEqual(['loading', 'guest', 'authed', 'guest'])
  })

  it('hands a late subscriber the current state, and stops calling one that unsubscribed', async () => {
    const { fetch } = await browserOverEngine()
    const store = createAuthStore<Profile>({ csrfCookieName: 'duck-csrf', fetch, noInitialFetch: true })
    let calls = 0
    store.state.subscribe(() => {
      calls++
    })()

    await store.signIn(credentials)
    expect(calls).toBe(1)
    let late = ''
    store.state.subscribe((state) => {
      late = state.status
    })()
    expect(late).toBe('authed')
  })
})
