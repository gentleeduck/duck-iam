// @vitest-environment jsdom
import { createElement } from 'react'
import { flushSync } from 'react-dom'
import { createRoot } from 'react-dom/client'
import { renderToString } from 'react-dom/server'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { browserOverEngine, type Profile } from '~/test/browser-over-engine'
import { createAuthClient, type VanillaClient } from '../../vanilla'
import { Provider, useSession, useSignIn, useSignOut, useSignUp } from '../index'
import type { ReactClient } from '../types'

afterEach(() => {
  vi.restoreAllMocks()
})

const credentials = { input: { email: 'a@x.com', password: 'correct-pw' }, providerId: 'password' }

/** Renders `<Provider {...props}><Child /></Provider>`; `read` runs on each render of the child, and the answer
 *  reads its latest result. */
function render<T>(props: ReactClient.IProviderProps<Profile>, read: () => T): () => T {
  let latest: { value: T } | undefined
  function Child() {
    latest = { value: read() }
    return null
  }
  const root = createRoot(document.createElement('div'))
  flushSync(() => root.render(createElement(Provider<Profile>, props, createElement(Child))))
  return () => {
    if (!latest) throw new Error('the provider rendered no children')
    return latest.value
  }
}

describe('the React binding', () => {
  it('signs in and out through a real engine, and re-renders with each state', async () => {
    const { adapter, fetch, id } = await browserOverEngine()
    const seen: string[] = []
    const auth = render({ csrfCookieName: 'duck-csrf', fetch }, () => {
      const session = useSession<Profile>()
      if (seen.at(-1) !== session.status) seen.push(session.status)
      return { session, signIn: useSignIn<Profile>(), signOut: useSignOut() }
    })
    await vi.waitFor(() => expect(auth().session.status).toBe('guest'))

    expect((await auth().signIn.mutate(credentials)).ok).toBe(true)
    await vi.waitFor(() => expect(auth().session.data.identity?.id).toBe(id))
    expect(auth().session.data.identity?.createdAt).toBeInstanceOf(Date)

    expect((await auth().signOut.mutate()).ok).toBe(true)
    expect(await adapter.sessions.listByIdentity(id)).toEqual([])
    await vi.waitFor(() => expect(auth().session.data.identity).toBeNull())
    expect(seen).toEqual(['loading', 'guest', 'authed', 'guest'])
  })

  it('renders `loading` while a mutation runs, then the error it threw, and clears it on the next', async () => {
    let fail: (err: Error) => void = () => {}
    const signIn = vi
      .fn<VanillaClient.Client<Profile>['signIn']>()
      .mockImplementationOnce(
        () =>
          new Promise((_, reject) => {
            fail = reject
          }),
      )
      .mockResolvedValueOnce({ code: 'AUTH_OK', data: { identity: null, session: null }, ok: true })
    const client = { ...createAuthClient<Profile>({ fetch: vi.fn() }), signIn }
    const auth = render({ client, noInitialFetch: true }, () => useSignIn<Profile>())

    const failing = auth().mutate(credentials)
    await vi.waitFor(() => expect(auth().loading).toBe(true))
    fail(new Error('reset'))
    await expect(failing).rejects.toThrow('reset')
    await vi.waitFor(() => expect(auth().error).toEqual(new Error('reset')))
    expect(auth().loading).toBe(false)

    await auth().mutate(credentials)
    await vi.waitFor(() => expect(auth().error).toBeNull())
  })

  it("posts the app's own sign-up shape to the app's own route", async () => {
    const fetch = vi.fn(async () => Response.json({ ok: true }))
    const auth = render({ baseUrl: 'http://app/api', fetch, noInitialFetch: true }, () =>
      useSignUp<{ email: string; password: string }>({ path: '/register' }),
    )

    expect(await auth().mutate({ email: 'a@x.com', password: 'pw' })).toMatchObject({ ok: true })
    expect(fetch).toHaveBeenCalledWith(
      'http://app/api/register',
      expect.objectContaining({ body: JSON.stringify({ email: 'a@x.com', password: 'pw' }), method: 'POST' }),
    )
  })

  it('refuses a hook outside a Provider, and answers inside one, rendered on the server', () => {
    function Status() {
      return useSession().status
    }
    expect(() => renderToString(createElement(Status))).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))

    const fetch = vi.fn()
    expect(renderToString(createElement(Provider, { fetch, noInitialFetch: true }, createElement(Status)))).toBe(
      'guest',
    )
    expect(fetch).not.toHaveBeenCalled()
  })
})
