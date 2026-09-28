import { createComponent, createComputed, createRoot } from 'solid-js'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { browserOverEngine, type Profile } from '~/test/browser-over-engine'
import { createAuthClient, type VanillaClient } from '../../vanilla'
import { authUseSession, authUseSignIn, authUseSignOut, Provider } from '../index'
import type { SolidClient } from '../types'

// Node resolves `solid-js` to its server build, where `onMount` never runs; a browser runs this one.
vi.mock('solid-js', () => vi.importActual('solid-js/dist/solid.js'))

afterEach(() => {
  vi.unstubAllGlobals()
})

/** `<Provider {...props}><Child /></Provider>` as babel-preset-solid compiles it, with `children` a getter;
 *  answers what the child returned. */
function render<T>(props: SolidClient.IProviderProps<Profile>, child: () => T): T {
  let rendered: { value: T } | undefined
  createRoot(() =>
    createComponent(Provider<Profile>, {
      ...props,
      get children() {
        rendered = { value: child() }
        return null
      },
    }),
  )
  if (!rendered) throw new Error('the provider rendered no children')
  return rendered.value
}

describe('the Solid binding', () => {
  it('signs in and out through a real engine, and its signals follow', async () => {
    const { adapter, fetch, id } = await browserOverEngine()
    const seen: string[] = []
    const auth = render({ csrfCookieName: 'duck-csrf', fetch }, () => {
      const session = authUseSession<Profile>()
      createComputed(() => seen.push(session.status()))
      return { session, signIn: authUseSignIn<Profile>(), signOut: authUseSignOut() }
    })
    await vi.waitFor(() => expect(auth.session.status()).toBe('guest'))

    const signedIn = await auth.signIn.mutate({
      input: { email: 'a@x.com', password: 'correct-pw' },
      providerId: 'password',
    })
    expect(signedIn.ok).toBe(true)
    expect(auth.session.data().identity?.id).toBe(id)
    expect(auth.session.data().identity?.createdAt).toBeInstanceOf(Date)

    expect((await auth.signOut.mutate()).ok).toBe(true)
    expect(await adapter.sessions.listByIdentity(id)).toEqual([])
    expect(auth.session.data().identity).toBeNull()
    expect(seen).toEqual(['loading', 'guest', 'authed', 'guest'])
  })

  it('holds `loading` while a mutation runs, keeps what it threw, and clears it on the next', async () => {
    const signIn = vi
      .fn<VanillaClient.Client<Profile>['signIn']>()
      .mockRejectedValueOnce(new Error('reset'))
      .mockResolvedValueOnce({ code: 'AUTH_OK', data: { identity: null, session: null }, ok: true })
    const client = { ...createAuthClient<Profile>({ fetch: vi.fn() }), signIn }
    const { error, loading, mutate } = render({ client, noInitialFetch: true }, () => authUseSignIn<Profile>())
    const opts = { input: {}, providerId: 'password' }

    const failing = mutate(opts)
    expect(loading()).toBe(true)
    await expect(failing).rejects.toThrow('reset')
    expect(loading()).toBe(false)
    expect(error()).toEqual(new Error('reset'))

    const passing = mutate(opts)
    expect(error()).toBeNull()
    await expect(passing).resolves.toMatchObject({ ok: true })
    expect(loading()).toBe(false)
  })

  it('refuses a primitive outside a Provider, and answers inside one', () => {
    expect(() => authUseSession()).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))

    const fetch = vi.fn()
    expect(render({ fetch, noInitialFetch: true }, () => authUseSession().status())).toBe('guest')
    expect(fetch).not.toHaveBeenCalled()
  })
})
