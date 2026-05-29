import { describe, expect, it } from 'vitest'
import { createMockClient, type StorybookAuth, withAuth } from '../index'

describe('storybook withAuth decorator', () => {
  it('createMockClient resolves getSession with the configured state', async () => {
    const client = createMockClient({
      status: 'authed',
      identity: { id: 'u1', providers: [], version: 1, createdAt: 0, updatedAt: 0 },
    })
    const result = await client.getSession()
    expect(result.identity?.id).toBe('u1')
  })

  it('createMockClient guest state has null identity + session', async () => {
    const client = createMockClient({ status: 'guest' })
    const r = await client.getSession()
    expect(r.identity).toBeNull()
    expect(r.session).toBeNull()
  })

  it('onChange fires once synchronously on subscribe', () => {
    const client = createMockClient({
      identity: { id: 'u2', providers: [], version: 1, createdAt: 0, updatedAt: 0 },
    })
    let seen: unknown = 'NOT-CALLED'
    const off = client.onChange((s) => {
      seen = s.identity?.id
    })
    off()
    expect(seen).toBe('u2')
  })

  it('signIn returns ok=true with the configured state', async () => {
    const client = createMockClient({
      identity: { id: 'u3', providers: [], version: 1, createdAt: 0, updatedAt: 0 },
    })
    const r = await client.signIn({ providerId: 'password', input: {} })
    expect(r.ok).toBe(true)
    expect(r.identity?.id).toBe('u3')
  })

  it('withAuth() returns a vnode wrapping AuthProvider', () => {
    const decorator = withAuth({ status: 'guest' })
    const result = decorator(() => null) as { type: unknown; props: { client: unknown } }
    expect(result).toBeDefined()
    expect(result.type).toBeDefined()
    expect(result.props.client).toBeDefined()
  })

  it('story-level parameters.auth merges over decorator defaults', async () => {
    const decorator = withAuth<{ email: string }>({ status: 'guest' })
    const result = decorator(() => null, {
      parameters: {
        auth: {
          status: 'authed',
          identity: {
            id: 'override',
            profile: { email: 'a@b.test' },
            providers: [],
            version: 1,
            createdAt: 0,
            updatedAt: 0,
          },
        },
      },
    }) as { props: { client: { getSession: () => Promise<{ identity: { id: string } | null }> } } }
    const sess = await result.props.client.getSession()
    expect(sess.identity?.id).toBe('override')
  })

  it('defaults flow through when no story-level parameters provided', async () => {
    const decorator = withAuth({
      identity: { id: 'from-defaults', providers: [], version: 1, createdAt: 0, updatedAt: 0 },
    })
    const result = decorator(() => null) as {
      props: { client: { getSession: () => Promise<{ identity: { id: string } | null }> } }
    }
    const sess = await result.props.client.getSession()
    expect(sess.identity?.id).toBe('from-defaults')
  })

  it('StorybookAuth.IState type is exported', () => {
    const _check: StorybookAuth.IState = {}
    expect(_check).toEqual({})
  })
})
