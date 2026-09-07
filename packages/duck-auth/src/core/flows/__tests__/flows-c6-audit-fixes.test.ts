/**
 * The last four open findings in `plans/C6-flows/AUDIT.md`, pinned.
 *
 *   F1  - `requestPasswordReset` was a timing oracle: one sha256 on the
 *         unknown-address branch against a write plus two reads on the known
 *         one, plus a channel misconfiguration that threw for a real address
 *         and answered `{ok:true}` for a fictional one.
 *   F8  - `requestEmailVerification` deleted every `recovery` credential for
 *         the identity, and four different flows share that kind.
 *   F9  - those four flows wrote two different discriminator keys, so the
 *         helper that reads one of them returned `undefined` for half of them.
 *   F21 - `beginSignUp` was the only flow that never consumed the limiter.
 *   F27 - `beginSignUp` built a profile with no `username`, which the type and
 *         duck-auth's own Postgres CHECK both require, and hid it with a cast.
 *
 * Each test is written to fail against the pre-fix code, not merely to describe
 * the post-fix code.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Channel } from '~/channels/channels.types'
import { AuthTestChannel } from '~/channels/console'
import { getCredentialPurpose, toCredentialUpsert } from '~/core/credentials/credentials'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function build(limit = 50) {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    limiter: new MemoryLimiter({ max: limit, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return { adapter, auth }
}

/** Count every store round trip the flow makes, in order. */
function traceStores(adapter: MemoryAdapter<MyProfile>): string[] {
  const calls: string[] = []
  for (const [store, names] of [
    ['credentials', ['upsert', 'listByIdentity', 'delete', 'findByHashedSecret', 'deleteByKind']],
    ['identities', ['findById', 'findByEmail', 'create', 'update']],
  ] as const) {
    const target = adapter[store] as unknown as Record<string, (...a: unknown[]) => unknown>
    for (const name of names) {
      const original = target[name]
      if (typeof original !== 'function') continue
      target[name] = (...args: unknown[]) => {
        calls.push(`${store}.${name}`)
        return original.apply(target, args)
      }
    }
  }
  return calls
}

describe('F1 - requestPasswordReset is not an enumeration oracle', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let known: string

  beforeEach(async () => {
    ;({ adapter, auth } = build())
    const ident = await auth.identities.create({ profile: { email: 'real@x.com', username: 'real' } })
    known = ident.id
  })

  const findByEmail = (id: string) => async (email: string) => (email === 'real@x.com' ? { id } : null)

  it('makes the same store calls, in the same order, whether or not the address exists', async () => {
    const hit = traceStores(adapter)
    await auth.flows.requestPasswordReset({
      channels: { email: new AuthTestChannel() },
      findIdentityByEmail: findByEmail(known),
      input: { email: 'real@x.com' },
    })
    const knownCalls = [...hit]

    const rebuilt = build()
    const miss = traceStores(rebuilt.adapter)
    await rebuilt.auth.flows.requestPasswordReset({
      channels: { email: new AuthTestChannel() },
      findIdentityByEmail: async () => null,
      input: { email: 'ghost@x.com' },
    })

    // Pre-fix the ghost branch made ZERO store calls and returned after one
    // sha256; the real one made three. Same count now, and the only difference
    // is the write the foreign key makes impossible to mirror.
    expect(miss).toHaveLength(knownCalls.length)
    expect(knownCalls[0]).toBe('credentials.upsert')
    expect(miss[0]).toBe('credentials.listByIdentity')
    expect(miss.slice(1)).toEqual(knownCalls.slice(1))
  })

  it('an unconfigured channel fails the same way for a real address and a fictional one', async () => {
    const ghost = auth.flows.requestPasswordReset({
      channels: {},
      findIdentityByEmail: findByEmail(known),
      input: { email: 'ghost@x.com' },
    })
    // Pre-fix this resolved `{ok:true}` while the real address threw - the
    // response body said "no such user" in plain language.
    await expect(ghost).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
    await expect(
      auth.flows.requestPasswordReset({
        channels: {},
        findIdentityByEmail: findByEmail(known),
        input: { email: 'real@x.com' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
  })

  it('still writes a usable token for the address that exists, and none for the one that does not', async () => {
    const channel = new AuthTestChannel()
    await auth.flows.requestPasswordReset({
      channels: { email: channel },
      findIdentityByEmail: findByEmail(known),
      input: { email: 'real@x.com' },
    })
    const rows = await adapter.credentials.listByIdentity(known, 'recovery', {})
    expect(rows).toHaveLength(1)
    expect(getCredentialPurpose(rows[0]!)).toBe('password-reset')

    const url = (channel.outbox[0]!.vars as { url: string }).url
    const token = new URL(url).searchParams.get('token')
    await expect(auth.flows.completePasswordReset({ newPassword: 'a-new-password-1', token: token! })).resolves.toEqual(
      { ok: true },
    )
  })

  it('does not emit recovery.password.requested for an address that does not exist', async () => {
    const seen = vi.fn()
    auth.events.on('recovery.password.requested', seen)
    await auth.flows.requestPasswordReset({
      channels: { email: new AuthTestChannel() },
      findIdentityByEmail: async () => null,
      input: { email: 'ghost@x.com' },
    })
    expect(seen).not.toHaveBeenCalled()
  })
})

describe('F8 / F9 - one credential kind, four flows, one discriminator', () => {
  let auth: AuthEngine<MyProfile>
  let adapter: MemoryAdapter<MyProfile>
  let identityId: string
  let channel: Channel.Channel & { outbox: unknown[] }

  beforeEach(async () => {
    ;({ adapter, auth } = build())
    const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } })
    identityId = ident.id
    channel = new AuthTestChannel()
  })

  async function plant(purpose: string, secret: string): Promise<void> {
    await adapter.credentials.upsert(
      toCredentialUpsert({ identityId, kind: 'recovery', metadata: { purpose }, secret }),
      {},
    )
  }

  it('requesting a verification mail leaves every other flow token alone', async () => {
    await plant('password-reset', 'hash-reset')
    await plant('account-deletion', 'hash-delete')
    await plant('signup-flow', 'hash-signup')

    await auth.flows.requestEmailVerification({ channels: { email: channel }, identityId })

    const rows = await adapter.credentials.listByIdentity(identityId, 'recovery', {})
    const purposes = rows.map((r) => getCredentialPurpose(r)).sort()
    // Pre-fix `deleteByKind(identityId, 'recovery')` took all three with it -
    // the user was thrown out of an in-flight signup and their pending reset
    // and deletion tokens were silently voided.
    expect(purposes).toEqual(['account-deletion', 'email-verification', 'password-reset', 'signup-flow'])
  })

  it('still replaces its own stale token, so two requests never leave two live links', async () => {
    await auth.flows.requestEmailVerification({ channels: { email: channel }, identityId })
    await auth.flows.requestEmailVerification({ channels: { email: channel }, identityId })
    const rows = await adapter.credentials.listByIdentity(identityId, 'recovery', {})
    expect(rows.filter((r) => getCredentialPurpose(r) === 'email-verification')).toHaveLength(1)
  })

  it('a signup-flow row answers getCredentialPurpose, which it never used to', async () => {
    const { flowToken } = await auth.flows.beginSignUp({ email: 'fresh@x.com' })
    void flowToken
    const created = await auth.identities.getByEmail('fresh@x.com')
    const rows = await adapter.credentials.listByIdentity(created!.id, 'recovery', {})
    // It wrote `metadata.kind`, so the helper every delete and guard reads
    // returned `undefined` and the row was invisible to all of them.
    expect(rows.map((r) => getCredentialPurpose(r))).toEqual(['signup-flow'])
  })
})

describe('F21 - beginSignUp is rate limited', () => {
  it('consumes the limiter and refuses once the window is spent', async () => {
    const { auth } = build(2)
    await auth.flows.beginSignUp({ email: 'one@x.com' })
    await auth.flows.beginSignUp({ email: 'one@x.com' }).catch(() => {})
    // Pre-fix this was unbounded: one unauthenticated request, one permanent
    // identity row, forever. It was the only flow in the unit with no consume.
    await expect(auth.flows.beginSignUp({ email: 'one@x.com' })).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
  })

  it('limits per address, so one attacker cannot lock out every signup', async () => {
    const { auth } = build(1)
    await auth.flows.beginSignUp({ email: 'first@x.com' })
    await expect(auth.flows.beginSignUp({ email: 'first@x.com' })).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    await expect(auth.flows.beginSignUp({ email: 'second@x.com' })).resolves.toBeTruthy()
  })
})

describe('F27 - beginSignUp builds a profile the identity store accepts', () => {
  it('derives a username when initialProfile carries none', async () => {
    const { auth } = build()
    await auth.flows.beginSignUp({ email: 'Nobody@Example.com' })
    const created = await auth.identities.getByEmail('Nobody@Example.com')
    // `ProfileMetadataBase` requires it and pg enforces it with a CHECK plus a
    // unique index; the old `as unknown as Profile` laundered a profile without
    // one straight into an INSERT the library's own adapter rejects.
    expect(created?.profile.username).toBe('Nobody@Example.com')
    expect(created?.profile.email).toBe('Nobody@Example.com')
  })

  it('keeps a username the caller supplied', async () => {
    const { auth } = build()
    await auth.flows.beginSignUp({ email: 'x@y.com', initialProfile: { username: 'chosen-handle' } })
    const created = await auth.identities.getByEmail('x@y.com')
    expect(created?.profile.username).toBe('chosen-handle')
  })

  it('does not collapse two different addresses onto one handle', async () => {
    const { auth } = build()
    await auth.flows.beginSignUp({ email: 'sam@a.com' })
    // `username` carries a unique index. Deriving from the local part would
    // refuse this second signup over a handle neither user picked.
    await expect(auth.flows.beginSignUp({ email: 'sam@b.com' })).resolves.toBeTruthy()
    expect((await auth.identities.getByEmail('sam@b.com'))?.profile.username).toBe('sam@b.com')
  })
})

describe('what these fixes did NOT close', () => {
  it('FINDING: beginSignUp still creates a real identity for an address nobody proved they own', async () => {
    // F21's other half. The limiter caps the rate; it does not stop the row
    // existing. An attacker still pre-claims `victim@corp.com`, and what the real
    // victim meets when they sign up is decided entirely by the host's own
    // findByEmail handling. Closing it means not writing the identity until the
    // address is verified - `DECISIONS.md` D1 option A - which the credentials
    // store cannot host today: `fk_auth_credentials_identity` requires the very
    // row that option defers, so the flow state has nowhere to live.
    const { auth } = build()
    await auth.flows.beginSignUp({ email: 'victim@corp.com' })
    expect(await auth.identities.getByEmail('victim@corp.com')).not.toBeNull()
  })

  it('FINDING: a second beginSignUp on a taken address says so, which answers who is registered', async () => {
    // The pre-created row makes the duplicate-email refusal reachable by anyone,
    // so signup reports account existence in a way `requestPasswordReset` goes to
    // some length to avoid. Same root cause as the finding above.
    const { auth } = build()
    await auth.flows.beginSignUp({ email: 'taken@corp.com' })
    await expect(auth.flows.beginSignUp({ email: 'taken@corp.com' })).rejects.toMatchObject({
      code: 'AUTH_EMAIL_TAKEN',
    })
  })

  it('FINDING: requestPasswordReset still spends a write on one branch and a read on the other', async () => {
    // The round-trip counts match and the crypto matches; what does not is that
    // the known-address branch writes a credential row and the unknown one reads
    // the same table instead. A write cannot be mirrored - the foreign key means
    // there is no row to hang a decoy on - so the residue is one write against
    // one read, measurable against a store where those differ enough to see.
    const { adapter, auth } = build()
    const ident = await auth.identities.create({ profile: { email: 'real@x.com', username: 'real' } })
    const calls = traceStores(adapter)
    await auth.flows.requestPasswordReset({
      channels: { email: new AuthTestChannel() },
      findIdentityByEmail: async () => ({ id: ident.id }),
      input: { email: 'real@x.com' },
    })
    expect(calls[0]).toBe('credentials.upsert')
  })

  it('FINDING: a password reset cannot be served at all unless the mfa provider is registered', async () => {
    // `requireMfa()` throws when the provider is absent, and the reset flow reads
    // it on every request to decide one template variable. A deployment with no
    // MFA gets AUTH_PROVIDER_NOT_REGISTERED out of a public endpoint rather than
    // a reset mail. Uniform across both branches now, which is what stops it
    // being an oracle, but it is still a hard dependency nothing declares.
    const adapter = new MemoryAdapter<MyProfile>()
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app',
      limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
      providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    await expect(
      auth.flows.requestPasswordReset({
        channels: { email: new AuthTestChannel() },
        findIdentityByEmail: async () => null,
        input: { email: 'ghost@x.com' },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_NOT_REGISTERED' })
  })
})
