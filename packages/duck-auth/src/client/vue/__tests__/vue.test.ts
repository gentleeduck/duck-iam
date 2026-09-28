import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, watch } from 'vue'
import { browserOverEngine, type Profile } from '~/test/browser-over-engine'
import { createAuthClient, type VanillaClient } from '../../vanilla'
import { createAuthVuePlugin, useAuthSession, useAuthSignIn, useAuthSignOut } from '../index'

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('the Vue binding', () => {
  it('signs in and out through a real engine, and its refs follow', async () => {
    const { adapter, fetch, id } = await browserOverEngine()
    const app = createApp({}).use(createAuthVuePlugin<Profile>({ csrfCookieName: 'duck-csrf', fetch }))
    const { data, status } = app.runWithContext(() => useAuthSession<Profile>())
    const seen = [status.value]
    watch(status, (now) => seen.push(now), { flush: 'sync' })
    await vi.waitFor(() => expect(status.value).toBe('guest'))

    const signIn = app.runWithContext(() => useAuthSignIn<Profile>())
    const signedIn = await signIn.mutate({
      input: { email: 'a@x.com', password: 'correct-pw' },
      providerId: 'password',
    })
    expect(signedIn.ok).toBe(true)
    expect(data.value.identity?.id).toBe(id)
    expect(data.value.identity?.createdAt).toBeInstanceOf(Date)

    const signOut = app.runWithContext(() => useAuthSignOut())
    expect((await signOut.mutate()).ok).toBe(true)
    expect(await adapter.sessions.listByIdentity(id)).toEqual([])
    expect(data.value.identity).toBeNull()
    expect(seen).toEqual(['loading', 'guest', 'authed', 'guest'])
  })

  it('holds `loading` while a mutation runs, keeps what it threw, and clears it on the next', async () => {
    const signIn = vi
      .fn<VanillaClient.Client<Profile>['signIn']>()
      .mockRejectedValueOnce(new Error('reset'))
      .mockResolvedValueOnce({ code: 'AUTH_OK', data: { identity: null, session: null }, ok: true })
    const client = { ...createAuthClient<Profile>({ fetch: vi.fn() }), signIn }
    const app = createApp({}).use(createAuthVuePlugin<Profile>({ client, noInitialFetch: true }))
    const { error, loading, mutate } = app.runWithContext(() => useAuthSignIn<Profile>())
    const opts = { input: {}, providerId: 'password' }

    const failing = mutate(opts)
    expect(loading.value).toBe(true)
    await expect(failing).rejects.toThrow('reset')
    expect(loading.value).toBe(false)
    expect(error.value).toEqual(new Error('reset'))

    const passing = mutate(opts)
    expect(error.value).toBeNull()
    await expect(passing).resolves.toMatchObject({ ok: true })
    expect(loading.value).toBe(false)
  })

  it('refuses a composable outside an app with the plugin, and answers inside one', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const misconfigured = expect.objectContaining({ code: 'AUTH_MISCONFIGURED' })
    expect(() => useAuthSession()).toThrow(misconfigured)
    expect(() => createApp({}).runWithContext(() => useAuthSignOut())).toThrow(misconfigured)

    const fetch = vi.fn()
    const app = createApp({}).use(createAuthVuePlugin({ fetch, noInitialFetch: true }))
    expect(app.runWithContext(() => useAuthSession()).status.value).toBe('guest')
    expect(fetch).not.toHaveBeenCalled()
  })
})
