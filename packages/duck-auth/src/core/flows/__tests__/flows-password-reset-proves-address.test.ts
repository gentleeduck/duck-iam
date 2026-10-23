/**
 * A reset link proves the address it went to, as a magic link does. On a row nobody had proven, whoever signed it
 * up may not be who holds the inbox, and a reset that kept what they linked or enrolled handed them the account
 * its owner had just recovered.
 */

import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Credential } from '~/core/credentials'
import { AuthEngine } from '~/core/engine'
import type { Deliver } from '~/core/flows/flows.delivery'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { apiKeyProvider } from '~/providers/api-key'
import { passwords, ScryptHasher } from '~/providers/passwords'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

/** An engine whose credential store calls `onSweep` on every whole-row read of the identity it is armed for. */
function buildAuth() {
  const adapter = new MemoryAdapter<MyProfile>()
  const urls: string[] = []
  const deliver: Deliver = async (m) => {
    urls.push(String(m.vars.url))
  }
  let armed: { id: string; onSweep: (read: number) => Promise<void>; reads: number } | null = null
  const credentials: Credential.Store = {
    ...adapter.credentials,
    listByIdentity: async (...args: Parameters<Credential.Store['listByIdentity']>) => {
      const rows = await adapter.credentials.listByIdentity(...args)
      if (armed && args[0] === armed.id && args[1] === null) await armed.onSweep(armed.reads++)
      return rows
    },
  }
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    deliver,
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), apiKeyProvider()],
    stores: { credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const arm = (id: string, onSweep: (read: number) => Promise<void>): void => {
    armed = { id, onSweep, reads: 0 }
  }
  return { adapter, arm, auth, urls }
}

type Built = ReturnType<typeof buildAuth>

/** A finished sign-up on the address, never proven, with a password, a linked IdP subject and an API key. */
async function signedUp({ adapter, auth }: Built) {
  const flow = await auth.flows.beginSignUp({ email: 'victim@x.com', required: [] })
  const id = flow.flow.identityId
  const { sid } = await auth.flows.completeSignUp({ flowToken: flow.flowToken })
  await auth.passwords.set(id, 'first-password-1', adapter.credentials, {})
  await auth.flows.linkProvider({
    authorize: async () => true,
    identityId: id,
    providerId: 'oauth:github',
    providerSub: 'gh',
  })
  const key = await auth.apiKeys.create(id, { name: 'k', scopes: [] })
  return { id, key: key.plaintext, sid }
}

async function reset({ auth, urls }: Built, id: string, currentSid?: string) {
  await auth.flows.requestPasswordReset({
    findIdentityByEmail: async (email) => (email === 'victim@x.com' ? { id } : null),
    input: { email: 'victim@x.com' },
  })
  const token = decodeURIComponent(new URL(urls.at(-1) ?? '').searchParams.get('token') ?? '')
  return auth.flows.completePasswordReset({
    newPassword: 'reset-password-2',
    token,
    ...(currentSid !== undefined && { currentSid }),
  })
}

describe('a password reset proves the address it was mailed to', () => {
  it('clears what was linked and enrolled on a row nobody had proven, and proves it', async () => {
    const built = buildAuth()
    const { id, key } = await signedUp(built)
    await reset(built, id)

    const row = await built.adapter.identities.find({ id })
    expect(row.emailVerified).toBe(true)
    expect(row.providers).toEqual([])
    await expect(built.auth.apiKeys.verify(key)).rejects.toBeInstanceOf(Error)
    expect((await built.auth.passwords.verify(id, 'first-password-1', built.adapter.credentials)).ok).toBe(false)
    expect((await built.auth.passwords.verify(id, 'reset-password-2', built.adapter.credentials)).ok).toBe(true)
  })

  it('keeps what a caller signed in to the row holds', async () => {
    const built = buildAuth()
    const { id, key, sid } = await signedUp(built)
    await reset(built, id, sid)

    const row = await built.adapter.identities.find({ id })
    expect(row.emailVerified).toBe(true)
    expect(row.providers.map((p) => p.providerId)).toEqual(['oauth:github'])
    await expect(built.auth.apiKeys.verify(key)).resolves.toMatchObject({ identityId: id })
  })

  it('leaves a proven row its links and keys', async () => {
    const built = buildAuth()
    const ident = await built.auth.identities.create({
      emailVerified: true,
      profile: { email: 'victim@x.com', username: 'victim' },
    })
    await built.auth.flows.linkProvider({
      authorize: async () => true,
      identityId: ident.id,
      providerId: 'oauth:github',
      providerSub: 'gh',
    })
    const key = await built.auth.apiKeys.create(ident.id, { name: 'k', scopes: [] })
    await reset(built, ident.id)

    expect((await built.adapter.identities.find({ id: ident.id })).providers).toHaveLength(1)
    await expect(built.auth.apiKeys.verify(key.plaintext)).resolves.toMatchObject({ identityId: ident.id })
  })

  it('leaves the address unproven when the clearing fails part-way, so the next reset clears it again', async () => {
    const built = buildAuth()
    const { id, key } = await signedUp(built)
    built.arm(id, async (read) => {
      if (read === 0) throw new Error('store is down')
    })
    await expect(reset(built, id)).rejects.toThrow('store is down')
    expect((await built.adapter.identities.find({ id })).emailVerified).toBe(false)

    await reset(built, id)
    expect((await built.adapter.identities.find({ id })).providers).toEqual([])
    await expect(built.auth.apiKeys.verify(key)).rejects.toBeInstanceOf(Error)
  })

  it('a sign-up begun while it clears the row cannot reclaim it as abandoned', async () => {
    const built = buildAuth()
    const { id } = await signedUp(built)
    let begun = ''
    built.arm(id, async (read) => {
      if (read !== 1) return
      begun = await built.auth.flows.beginSignUp({ email: 'victim@x.com', required: [] }).then(
        () => 'reclaimed',
        (err: { code?: string }) => err.code ?? 'threw',
      )
    })
    await reset(built, id)
    expect(begun).toBe('AUTH_EMAIL_TAKEN')
  })
})
