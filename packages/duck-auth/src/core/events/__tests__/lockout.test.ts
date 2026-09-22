/** D3 - `strict()` demanded a `lockout` handler for an event nothing emitted. */

import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthTestChannel } from '~/channels/console'
import { orNull } from '~/core/answer'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import { InMemoryEvents } from '~/core/events'
import { refuseRateLimited } from '~/core/events/events.lockout'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { authApiKey } from '~/providers/api-key'
import { ApiKeysFacet } from '~/providers/api-key/api-key'
import { magicLink } from '~/providers/magic-link'
import { mfaProvider, totpAt } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { identityInput } from '~/test/store-inputs'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

type Lockout = { identityId: string; until: number }

function build(limit: number) {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    limiter: new MemoryLimiter({ max: limit, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const seen: Lockout[] = []
  auth.events.on('lockout', (p) => {
    seen.push(p)
  })
  return { adapter, auth, seen }
}

async function newIdentity(auth: AuthEngine<MyProfile>, email: string): Promise<string> {
  const ident = await auth.identities.create({ profile: { email, username: email } })
  return ident.id
}

function tokenFrom(channel: AuthTestChannel): string {
  const url = (channel.outbox.at(-1)?.vars as { url: string }).url
  return new URL(url).searchParams.get('token') ?? ''
}

describe('refuseRateLimited', () => {
  it('never hands back Retry-After: 0', async () => {
    const events = new InMemoryEvents()
    // A window that closed a millisecond ago: `Math.max(0, …)` - what seven of
    // the eight sites used - answers 0, telling the client to retry at once.
    await expect(
      refuseRateLimited(events, { ok: false, remaining: 0, resetAt: new Date(Date.now() - 1) }, null),
    ).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED', meta: { retryAfter: 1 } })
  })

  it('a limiter returning a broken resetAt still refuses, instead of throwing a TypeError', async () => {
    const events = new InMemoryEvents()
    // Every site did `limited.resetAt.getTime()` unguarded. An adapter handing
    // back an invalid Date turned a 429 into `NaN`; one handing back a number
    // turned it into a 500, and the limit stopped applying at all.
    await expect(
      refuseRateLimited(events, { ok: false, remaining: 0, resetAt: new Date(Number.NaN) }, null),
    ).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    const broken = { ok: false, remaining: 0, resetAt: Date.now() + 60_000 } as unknown as {
      ok: boolean
      remaining: number
      resetAt: Date
    }
    await expect(refuseRateLimited(events, broken, null)).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
  })

  it('emits nothing when there is no subject to name', async () => {
    const events = new InMemoryEvents()
    const handler = vi.fn()
    events.on('lockout', handler)
    await expect(
      refuseRateLimited(events, { ok: false, remaining: 0, resetAt: new Date(Date.now() + 1000) }, null),
    ).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    // An empty string is not a subject either - it is a store that lost an id.
    await expect(
      refuseRateLimited(events, { ok: false, remaining: 0, resetAt: new Date(Date.now() + 1000) }, ''),
    ).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    expect(handler).not.toHaveBeenCalled()
  })
})

describe('lockout is emitted where the refusal knows whose account it is', () => {
  it('password sign-in - the brute-force bucket names the account being ground', async () => {
    const { adapter, auth, seen } = build(1)
    const id = await newIdentity(auth, 'alice@x.com')
    await auth.passwords.set(id, 'correct-horse-battery', adapter.credentials)

    const attempt = () =>
      auth.flows.signIn({ input: { email: 'alice@x.com', password: 'wrong-password-1' }, providerId: 'password' })

    await expect(attempt()).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
    expect(seen).toEqual([])

    await expect(attempt()).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    expect(seen).toHaveLength(1)
    expect(seen[0]?.identityId).toBe(id)
    expect(seen[0]?.until).toBeGreaterThan(Date.now())
  })

  it('password sign-in - a correct password is refused and reported the same way', async () => {
    const { adapter, auth, seen } = build(1)
    const id = await newIdentity(auth, 'alice@x.com')
    await auth.passwords.set(id, 'correct-horse-battery', adapter.credentials)

    const signin = () =>
      auth.flows.signIn({ input: { email: 'alice@x.com', password: 'correct-horse-battery' }, providerId: 'password' })
    await signin()
    await expect(signin()).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    expect(seen.map((s) => s.identityId)).toEqual([id])
  })

  it('password sign-in - an address with no account behind it stays anonymous', async () => {
    const { auth, seen } = build(1)
    const attempt = () =>
      auth.flows.signIn({ input: { email: 'ghost@x.com', password: 'wrong-password-1' }, providerId: 'password' })
    await expect(attempt()).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
    await expect(attempt()).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    expect(seen).toEqual([])
  })

  it('requestEmailVerification - the resend bucket names its identity', async () => {
    const { auth, seen } = build(1)
    const id = await newIdentity(auth, 'bob@x.com')
    const channel = new AuthTestChannel()

    await auth.flows.requestEmailVerification({ channels: { email: channel }, identityId: id })
    await expect(
      auth.flows.requestEmailVerification({ channels: { email: channel }, identityId: id }),
    ).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })

    expect(seen).toHaveLength(1)
    expect(seen[0]?.identityId).toBe(id)
  })

  it('requestAccountDeletion - names its identity', async () => {
    const { auth, seen } = build(1)
    const id = await newIdentity(auth, 'carol@x.com')
    const channel = new AuthTestChannel()

    await auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: id })
    await expect(
      auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: id }),
    ).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    expect(seen.map((s) => s.identityId)).toEqual([id])
  })

  it('requestAccountDeletion - an id with no row never reaches the limiter', async () => {
    const { auth, seen } = build(1)
    const channel = new AuthTestChannel()
    // The consume used to run above the lookup, so the second call answered
    // `AUTH_RATE_LIMITED` for an identity that does not exist - and, once the
    // guard emitted, would have paged an operator about a phantom account.
    for (let i = 0; i < 3; i++) {
      await expect(
        auth.flows.requestAccountDeletion({ channels: { email: channel }, identityId: 'no-such-id' }),
      ).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
    }
    expect(seen).toEqual([])
  })

  it('completePasswordReset - a ground MFA gate names the token owner', async () => {
    const { auth, seen } = build(1)
    const id = await newIdentity(auth, 'dave@x.com')
    const enrol = await auth.mfa.beginTotpEnrollment(id, 'dave@x.com')
    await auth.mfa.confirmTotpEnrollment(id, totpAt(enrol.secret, Math.floor(Date.now() / 1000 / 30)))

    const channel = new AuthTestChannel()
    await auth.flows.requestPasswordReset({
      channels: { email: channel },
      findIdentityByEmail: (email) => auth.identities.getByEmail(email),
      input: { email: 'dave@x.com' },
    })
    const token = tokenFrom(channel)

    // First call: refused for MFA, one unit of the gate's bucket spent.
    await expect(auth.flows.completePasswordReset({ newPassword: 'new-password-9', token })).rejects.toMatchObject({
      code: 'AUTH_RECOVERY_REQUIRES_MFA',
    })
    expect(seen).toEqual([])

    // Second: bucket spent, token burnt, and the operator hears about it.
    await expect(auth.flows.completePasswordReset({ newPassword: 'new-password-9', token })).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    })
    expect(seen.map((s) => s.identityId)).toEqual([id])
  })
})

describe('lockout is withheld where the refusal has no subject', () => {
  it('beginSignUp - the address has no account behind it yet', async () => {
    const { auth, seen } = build(1)
    await auth.flows.beginSignUp({ email: 'new@x.com' })
    await expect(auth.flows.beginSignUp({ email: 'new@x.com' })).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    expect(seen).toEqual([])
  })

  it('requestPasswordReset - resolving the address means running host code on a refused request', async () => {
    const { auth, seen } = build(1)
    await newIdentity(auth, 'erin@x.com')
    const channel = new AuthTestChannel()
    const findIdentityByEmail = vi.fn((email: string) => auth.identities.getByEmail(email))

    const request = () =>
      auth.flows.requestPasswordReset({
        channels: { email: channel },
        findIdentityByEmail,
        input: { email: 'erin@x.com' },
      })

    await request()
    await expect(request()).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    expect(seen).toEqual([])
    // And the refused call did not call out to the host at all.
    expect(findIdentityByEmail).toHaveBeenCalledTimes(1)
  })

  it('magic-link - a spent bucket stops a mail, it does not lock an account', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      limiter: new MemoryLimiter({ max: 1, windowMs: 60_000 }),
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    const seen: Lockout[] = []
    auth.events.on('lockout', (p) => {
      seen.push(p)
    })
    const channel = new AuthTestChannel()
    auth.providers.register(
      magicLink<MyProfile>({
        channels: { email: channel },
        findIdentityByEmail: (email) => orNull(adapter.identities.find({ email })),
      }),
    )
    await auth.identities.create({ profile: { email: 'frank@x.com', username: 'frank@x.com' } })

    await auth.flows.beginProvider('magic-link', { email: 'frank@x.com' })
    await expect(auth.flows.beginProvider('magic-link', { email: 'frank@x.com' })).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    })
    expect(seen).toEqual([])
  })

  it('api-key - the only route from the bucket key to a subject is the verification being shed', async () => {
    const adapter = new MemoryAdapter<MyProfile>()
    const events = new InMemoryEvents()
    const handler = vi.fn()
    events.on('lockout', handler)
    const facet = new ApiKeysFacet(adapter.credentials, events, { randomToken, sha256 })
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'svc@x.com', username: 'svc' }, providers: [] }),
    )
    const { plaintext } = await facet.create(ident.id, { name: 'CI runner', scopes: ['read:users'] })
    const ctx = {
      baseUrl: 'https://app',
      crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
      events,
      limiter: new MemoryLimiter({ max: 1, windowMs: 60_000 }),
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      tenant: {},
    }
    const provider = authApiKey<MyProfile>({ apiKeys: facet })

    await provider.complete(ctx, { token: plaintext })
    await expect(provider.complete(ctx, { token: plaintext })).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    expect(handler).not.toHaveBeenCalled()
  })
})
