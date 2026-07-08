import { describe, expect, it } from 'vitest'
import { authCreateMockClient, authWithStorybook, type Storybook } from '../index'

describe('storybook authWithStorybook decorator', () => {
  it('authCreateMockClient resolves getSession with the configured state', async () => {
    const client = authCreateMockClient({
      status: 'authed',
      identity: { id: 'u1', providers: [], version: 1, createdAt: new Date(0), updatedAt: new Date(0) },
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
      identity: { id: 'u2', providers: [], version: 1, createdAt: new Date(0), updatedAt: new Date(0) },
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
      identity: { id: 'u3', providers: [], version: 1, createdAt: new Date(0), updatedAt: new Date(0) },
    })
    const r = await client.signIn({ providerId: 'password', input: {} })
    expect(r.ok).toBe(true)
    if (!r.ok) throw new Error('expected ok')
    expect(r.data.identity?.id).toBe('u3')
  })

  it('authWithStorybook() returns a vnode wrapping Provider', () => {
    const decorator = authWithStorybook({ status: 'guest' })
    const result = decorator(() => null) as { type: unknown; props: { client: unknown } }
    expect(result).toBeDefined()
    expect(result.type).toBeDefined()
    expect(result.props.client).toBeDefined()
  })

  it('story-level parameters.auth merges over decorator defaults', async () => {
    const decorator = authWithStorybook<{ username: string; email: string }>({ status: 'guest' })
    const result = decorator(() => null, {
      parameters: {
        auth: {
          status: 'authed',
          identity: {
            id: 'override',
            profile: { username: 'a@b.test', email: 'a@b.test' },
            providers: [],
            version: 1,
            createdAt: new Date(0),
            updatedAt: new Date(0),
          },
        },
      },
    }) as {
      props: {
        client: { getSession: () => Promise<{ ok: true; data: { identity: { id: string } | null } } | { ok: false }> }
      }
    }
    const sess = await result.props.client.getSession()
    expect((sess.ok ? sess.data : null)?.identity?.id).toBe('override')
  })

  it('defaults flow through when no story-level parameters provided', async () => {
    const decorator = authWithStorybook({
      identity: { id: 'from-defaults', providers: [], version: 1, createdAt: new Date(0), updatedAt: new Date(0) },
    })
    const result = decorator(() => null) as {
      props: {
        client: { getSession: () => Promise<{ ok: true; data: { identity: { id: string } | null } } | { ok: false }> }
      }
    }
    const sess = await result.props.client.getSession()
    expect((sess.ok ? sess.data : null)?.identity?.id).toBe('from-defaults')
  })

  it('Storybook.State type is exported', () => {
    const _check: Storybook.State = {}
    expect(_check).toEqual({})
  })
})
