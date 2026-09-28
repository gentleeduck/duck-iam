// @vitest-environment jsdom
import { flushSync } from 'react-dom'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'
import { useSession } from '../../index'
import { authCreateMockClient, authWithStorybook, type Storybook } from '../index'

type Profile = { email: string; username: string }

function identity(id: string) {
  return { createdAt: new Date(0), id, providers: [], updatedAt: new Date(0), version: 1 }
}

/** The identity id a story reads through `useSession` under the decorator, once its Provider has subscribed. */
async function storyIdentity(defaults: Storybook.State<Profile>, auth?: Partial<Storybook.State<Profile>>) {
  let id: string | undefined
  function Story() {
    id = useSession<Profile>().data.identity?.id
    return null
  }
  flushSync(() =>
    createRoot(document.createElement('div')).render(authWithStorybook(defaults)(Story, { parameters: { auth } })),
  )
  await vi.waitFor(() => expect(id).toBeDefined())
  return id
}

describe('storybook authWithStorybook decorator', () => {
  it('authCreateMockClient resolves getSession with the configured state', async () => {
    const client = authCreateMockClient({
      status: 'authed',
      identity: identity('u1'),
    })
    const result = await client.getSession()
    if (!result.ok) throw new Error('expected ok')
    expect(result.data.identity?.id).toBe('u1')
  })

  it('authCreateMockClient guest state has null identity + session', async () => {
    const client = authCreateMockClient({ status: 'guest' })
    const r = await client.getSession()
    if (!r.ok) throw new Error('expected ok')
    expect(r.data.identity).toBeNull()
    expect(r.data.session).toBeNull()
  })

  it('onChange fires once synchronously on subscribe', () => {
    const client = authCreateMockClient({
      identity: identity('u2'),
    })
    let seen: unknown = 'NOT-CALLED'
    const off = client.onChange((s) => {
      seen = s.identity?.id
    })
    off()
    expect(seen).toBe('u2')
  })

  it('signIn returns ok=true with the configured state', async () => {
    const client = authCreateMockClient({
      identity: identity('u3'),
    })
    const r = await client.signIn({ providerId: 'password', input: {} })
    expect(r.ok).toBe(true)
    if (!r.ok) throw new Error('expected ok')
    expect(r.data.identity?.id).toBe('u3')
  })

  it('renders the story under a Provider holding the configured identity', async () => {
    expect(await storyIdentity({ identity: identity('from-defaults') })).toBe('from-defaults')
  })

  it("lets a story's `parameters.auth` override the decorator's defaults", async () => {
    expect(await storyIdentity({ identity: identity('from-defaults') }, { identity: identity('override') })).toBe(
      'override',
    )
  })
})
