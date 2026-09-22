/**
 * `completePasswordReset` resolved its tenant on every store call but the last one, the write that
 * actually swaps the password. `PasswordsImpl.set` defaults its tenant context to `{}`, and an
 * undefined tenant is not "this tenant" - `inTenant` emits no filter at all, and `create` stamps
 * `tenantId: null`. So the reset deleted the password row in every tenant and wrote its replacement
 * into none of them.
 */

import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import type { Channel } from '~/channels/channels.types'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { identityInput } from '~/test/store-inputs'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function buildAuth(): { auth: AuthEngine<MyProfile>; adapter: MemoryAdapter<MyProfile> } {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return { adapter, auth }
}

/** Captures the link so the test can claim the token the way the recipient would. */
function capturingChannel(): Channel.Channel & { urls: string[] } {
  const ch = {
    id: 'capture',
    kind: 'email' as const,
    async send(msg: { vars: Record<string, unknown> }): Promise<{ ok: true }> {
      ch.urls.push(String(msg.vars.url))
      return { ok: true }
    },
    urls: [] as string[],
  }
  return ch as Channel.Channel & { urls: string[] }
}

async function resetPassword(
  auth: AuthEngine<MyProfile>,
  identityId: string,
  email: string,
  newPassword: string,
  tenantId: string,
): Promise<void> {
  const channel = capturingChannel()
  await auth.flows.requestPasswordReset({
    channels: { email: channel },
    findIdentityByEmail: async () => ({ id: identityId }),
    input: { email },
    tenantId,
  })
  const url = channel.urls[0]
  if (url === undefined) throw new Error('no reset link was dispatched')
  const token = decodeURIComponent(new URL(url).searchParams.get('token') ?? '')
  await auth.flows.completePasswordReset({ newPassword, tenantId, token })
}

describe('completePasswordReset writes the new password into the tenant it was asked for', () => {
  it('the password it just set is the one that signs in', async () => {
    const { adapter, auth } = buildAuth()
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@x.com', username: 'a@x.com' }, providers: [] }),
    )
    await auth.passwords.set(ident.id, 'old-password-123', adapter.credentials, { tenantId: 'tenant-a' })

    await resetPassword(auth, ident.id, 'a@x.com', 'new-password-456', 'tenant-a')

    const out = await auth.flows.signIn({
      input: { email: 'a@x.com', password: 'new-password-456' },
      providerId: 'password',
      tenantId: 'tenant-a',
    })
    expect(out.session).not.toBeNull()
  })

  it('the replacement row carries the tenant, not null', async () => {
    const { adapter, auth } = buildAuth()
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@x.com', username: 'a@x.com' }, providers: [] }),
    )
    await auth.passwords.set(ident.id, 'old-password-123', adapter.credentials, { tenantId: 'tenant-a' })

    await resetPassword(auth, ident.id, 'a@x.com', 'new-password-456', 'tenant-a')

    const scoped = await adapter.credentials.listByIdentity(ident.id, 'password', { tenantId: 'tenant-a' })
    expect(scoped).toHaveLength(1)
    expect(scoped[0]?.tenantId).toBe('tenant-a')
  })

  it('a reset in one tenant leaves the other tenant password alone', async () => {
    const { adapter, auth } = buildAuth()
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'a@x.com', username: 'a@x.com' }, providers: [] }),
    )
    await auth.passwords.set(ident.id, 'tenant-a-password', adapter.credentials, { tenantId: 'tenant-a' })
    await auth.passwords.set(ident.id, 'tenant-b-password', adapter.credentials, { tenantId: 'tenant-b' })

    await resetPassword(auth, ident.id, 'a@x.com', 'new-password-456', 'tenant-a')

    const out = await auth.flows.signIn({
      input: { email: 'a@x.com', password: 'tenant-b-password' },
      providerId: 'password',
      tenantId: 'tenant-b',
    })
    expect(out.session).not.toBeNull()
  })
})
