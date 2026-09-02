import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Channel } from '~/channels/channels.types'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities'
import { M2MImpl } from '~/core/m2m/m2m'
import { JwtTransport } from '~/core/transport/jwt.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { apiKeyProvider } from '~/providers/api-key'
import { magicLink } from '~/providers/magic-link'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'

/**
 * Deleting an account must end every way into it, not just the ones that go
 * through `flows.signIn`.
 *
 * `signIn` re-reads the identity behind a `startSession` intent, so every
 * sign-in provider was already covered. The credential-first surfaces were not:
 * they resolve a credential row and hand back `row.identityId` without ever
 * looking at the identity, so an API key kept working - and `M2MImpl.exchange`
 * turned one into a live bearer token - long after the account was deleted.
 */
interface P extends Identities.ProfileMetadataBase {}

function fakeChannel(): Channel.Channel & { sent: Array<{ url: string }> } {
  const sent: Array<{ url: string }> = []
  return {
    id: 'fake',
    kind: 'email',
    async send(input) {
      sent.push({ url: (input.vars as { url?: string }).url ?? '' })
      return { ok: true }
    },
    sent,
  }
}

function build() {
  const adapter = new MemoryAdapter<P>()
  const channel = fakeChannel()
  const auth = new AuthEngine<P>({
    baseUrl: 'https://app.test',
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [apiKeyProvider(), passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new JwtTransport({
      issuer: 'https://app.test',
      signKey: { key: 'secret-32-bytes-of-test-material', kid: 'k1' },
      ttlMs: 3_600_000,
      verifyKeys: [{ key: 'secret-32-bytes-of-test-material', kid: 'k1' }],
    }),
  })
  auth.providers.register(
    magicLink<P>({
      autoCreateIdentity: true,
      autoCreateProfile: (email) => ({ email, username: email }),
      channels: { email: channel },
      findIdentityByEmail: (email) => adapter.identities.findByEmail(email),
      ttlMs: 60_000,
    }),
  )
  return { adapter, auth, channel }
}

async function issueKey(auth: AuthEngine<P>, identityId: string) {
  const created = await auth.apiKeys.create(identityId, { name: 'ci', scopes: ['read:users'] })
  return { plaintext: created.plaintext, id: created.key.id }
}

describe('a deleted identity cannot be authenticated', () => {
  it('api-key verify works while the identity is live (control)', async () => {
    const { auth } = build()
    const i = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } })
    const key = await issueKey(auth, i.id)

    // Without this the negative cases below would pass against a key that never
    // worked in the first place.
    expect((await auth.apiKeys.verify(key.plaintext)).identityId).toBe(i.id)
  })

  it('api-key verify refuses a key whose identity was soft-deleted', async () => {
    const { auth } = build()
    const i = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } })
    const key = await issueKey(auth, i.id)

    await auth.identities.softDelete(i.id)

    // Same code as an unknown key: whether the id still exists is not something
    // an unauthenticated caller gets to probe.
    await expect(auth.apiKeys.verify(key.plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_INVALID' })
  })

  it('api-key verify refuses a key whose identity was erased', async () => {
    const { adapter, auth } = build()
    const i = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } })
    const key = await issueKey(auth, i.id)

    await adapter.identities.erase(i.id)

    await expect(auth.apiKeys.verify(key.plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_INVALID' })
  })

  it('m2m exchange mints no token for a soft-deleted identity', async () => {
    const { auth } = build()
    const i = await auth.identities.create({ profile: { email: 'm@x.com', username: 'm' } })
    const key = await issueKey(auth, i.id)
    const m2m = new M2MImpl(auth.apiKeys, auth.sessions, auth.transport)

    // Live first, so the exchange is known to work before deletion breaks it.
    expect((await m2m.exchange({ clientId: key.id, clientSecret: key.plaintext })).token_type).toBe('Bearer')

    await auth.identities.softDelete(i.id)

    await expect(m2m.exchange({ clientId: key.id, clientSecret: key.plaintext })).rejects.toMatchObject({
      code: 'AUTH_APIKEY_INVALID',
    })
  })

  it('a magic-link token issued before the deletion no longer signs in', async () => {
    const { adapter, auth, channel } = build()
    await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
    const token = new URL(channel.sent[0]?.url ?? '').searchParams.get('token') ?? ''
    const i = await adapter.identities.findByEmail('a@x.com')

    await auth.identities.softDelete(i?.id ?? '')

    // Pins the central guard in `flows.signIn`, which is why the sign-in
    // providers never needed a check of their own.
    await expect(auth.flows.signIn({ input: { token }, providerId: 'magic-link' })).rejects.toMatchObject({
      code: 'AUTH_UNAUTHENTICATED',
    })
  })

  it('a password reset no longer completes against a soft-deleted account', async () => {
    const { adapter, auth, channel } = build()
    const ident = await auth.identities.create({ profile: { email: 'r@x.com', username: 'r' } })

    await auth.flows.requestPasswordReset({
      channels: { email: channel },
      findIdentityByEmail: async () => ({ id: ident.id }),
      input: { email: 'r@x.com' },
    })
    const token = new URL(channel.sent.at(-1)?.url ?? '').searchParams.get('token') ?? ''

    await auth.identities.softDelete(ident.id)
    expect(await adapter.identities.findById(ident.id)).toBeNull()

    // Reported as an invalid token, not a distinct code: a reset link must not
    // double as a way to ask whether an account still exists.
    await expect(auth.flows.completePasswordReset({ newPassword: 'a-new-password-1', token })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
  })

  it('an account-deletion token no longer completes once the identity is erased', async () => {
    const { adapter, auth, channel } = build()
    const ident = await auth.identities.create({ profile: { email: 'del@x.com', username: 'del' } })

    await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: ident.id })
    const token = new URL(channel.sent.at(-1)?.url ?? '').searchParams.get('token') ?? ''

    await adapter.identities.erase(ident.id)

    // The token is valid and its credential row still resolves, but there is
    // no longer an account to delete. Reporting `{ ok }` with a restore
    // deadline would promise a grace window over nothing.
    await expect(auth.flows.completeAccountDeletion({ token })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_TOKEN_INVALID',
    })
  })

  it('an account-deletion token completes for a live identity (control)', async () => {
    const { auth, channel } = build()
    const ident = await auth.identities.create({ profile: { email: 'del2@x.com', username: 'del2' } })

    await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: ident.id })
    const token = new URL(channel.sent.at(-1)?.url ?? '').searchParams.get('token') ?? ''

    // Without this the refusal above would also pass against a deletion flow
    // that was simply broken for everyone.
    const done = await auth.flows.completeAccountDeletion({ token })
    expect(done.identity.id).toBe(ident.id)
  })

  it('a password reset still completes for a live identity (control)', async () => {
    const { auth, channel } = build()
    const ident = await auth.identities.create({ profile: { email: 'live@x.com', username: 'live' } })

    await auth.flows.requestPasswordReset({
      channels: { email: channel },
      findIdentityByEmail: async () => ({ id: ident.id }),
      input: { email: 'live@x.com' },
    })
    const token = new URL(channel.sent.at(-1)?.url ?? '').searchParams.get('token') ?? ''

    // Without this the refusal above would also pass against a reset flow that
    // was simply broken for everyone.
    await expect(auth.flows.completePasswordReset({ newPassword: 'a-new-password-1', token })).resolves.toBeDefined()
  })
})
