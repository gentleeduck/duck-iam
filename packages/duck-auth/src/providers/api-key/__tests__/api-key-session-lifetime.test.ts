import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { identityInput } from '~/test/store-inputs'
import { apiKeyProvider, authApiKey } from '../api-key'

async function build() {
  const adapter = new MemoryAdapter()
  const auth = new AuthEngine({
    baseUrl: 'https://app.test',
    transport: new CookieTransport(),
    stores: { identities: adapter.identities, sessions: adapter.sessions, credentials: adapter.credentials },
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    providers: [apiKeyProvider(), (engine) => authApiKey({ apiKeys: engine.apiKeys })],
  })
  const identity = await adapter.identities.create(
    identityInput({ profile: { username: 'svc', email: 'svc@app.test' }, providers: [] }),
  )
  const browser = await auth.sessions.create({ identityId: identity.id, kind: 'user', aal: 1, factors: [] })
  const signIn = async (token: string) => {
    const out = await auth.flows.signIn({ providerId: 'api-key', input: { token } })
    if (!out.session) throw new Error('no session')
    return out.session
  }
  return { adapter, auth, identity, browser, signIn }
}

describe('a session an api key signed in', () => {
  it('is an apikey session, not a user one', async () => {
    const { auth, identity, signIn } = await build()
    const { plaintext } = await auth.apiKeys.create(identity.id, { name: 'ci', scopes: [] })
    expect((await signIn(plaintext)).kind).toBe('apikey')
  })

  it('ends when the key is revoked, and the owner stays signed in elsewhere', async () => {
    const { adapter, auth, identity, browser, signIn } = await build()
    const created = await auth.apiKeys.create(identity.id, { name: 'ci', scopes: [] })
    const session = await signIn(created.plaintext)
    await auth.apiKeys.revoke(created.key.id)
    await expect(adapter.sessions.getByHash(session.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    await expect(adapter.sessions.getByHash(browser.session.id)).resolves.toBeDefined()
  })

  it('ends when every key is revoked at once', async () => {
    const { adapter, auth, identity, signIn } = await build()
    const session = await signIn((await auth.apiKeys.create(identity.id, { name: 'ci', scopes: [] })).plaintext)
    await auth.apiKeys.revokeAll(identity.id)
    await expect(adapter.sessions.getByHash(session.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('ends when the key is rotated', async () => {
    const { adapter, auth, identity, signIn } = await build()
    const created = await auth.apiKeys.create(identity.id, { name: 'ci', scopes: [] })
    const session = await signIn(created.plaintext)
    await auth.apiKeys.rotate(created.key.id)
    await expect(adapter.sessions.getByHash(session.id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })
})
