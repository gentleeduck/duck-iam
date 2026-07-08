import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { passwordProvider } from '../../../providers/password'
import { ScryptHasher } from '../../../providers/password/hashers/scrypt.hasher'
import { credentialInput, identityInput } from '../../../test/store-inputs'
import { AuthEngine } from '../../engine'
import { CookieTransport } from '../../transport/cookie'
import type { Identity } from '../../types/identity'
import type { Channel } from '../../types/infra'

interface MyProfile extends Identity.ProfileMetadataBase {
  email: string
}

function buildAuth(): { auth: AuthEngine<MyProfile>; adapter: MemoryAdapter<MyProfile> } {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwordProvider({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
  })
  return { auth, adapter }
}

function makeSlowChannel(delayMs: number): Channel.Channel & { sendStarted: number } {
  const ch = {
    kind: 'email' as const,
    id: 'slow',
    sendStarted: 0,
    async send(): Promise<{ ok: true }> {
      ch.sendStarted++
      await new Promise((r) => setTimeout(r, delayMs))
      return { ok: true }
    },
  }
  return ch
}

describe('flows.requestPasswordReset - timing-defense', () => {
  it('existing-email branch returns BEFORE channel.send resolves (fire-and-forget)', async () => {
    const channel = makeSlowChannel(200)
    const { auth, adapter } = buildAuth()
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'a@x.com', email: 'a@x.com' }, providers: [] }),
      {},
    )
    const findIdentityByEmail = async (): Promise<{ id: string } | null> => ({ id: ident.id })

    const start = performance.now()
    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail,
      channels: { email: channel },
    })
    const elapsed = performance.now() - start
    // The handler returned in tens of ms (token mint + upsert + hasTotp +
    // event emit), NOT after the 200 ms channel delay.
    expect(elapsed).toBeLessThan(100)
    // But channel.send WAS scheduled.
    expect(channel.sendStarted).toBe(1)
  })

  it('non-existing-email branch returns at the same wall-clock cost (within 50 ms)', async () => {
    const channel = makeSlowChannel(200)
    const { auth, adapter } = buildAuth()
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'existing@x.com', email: 'existing@x.com' }, providers: [] }),
      {},
    )
    const findIdentityByEmail = async (email: string): Promise<{ id: string } | null> =>
      email === 'existing@x.com' ? { id: ident.id } : null

    const existsStart = performance.now()
    await auth.flows.requestPasswordReset({
      input: { email: 'existing@x.com' },
      findIdentityByEmail,
      channels: { email: channel },
    })
    const existsElapsed = performance.now() - existsStart

    const ghostStart = performance.now()
    await auth.flows.requestPasswordReset({
      input: { email: 'ghost@x.com' },
      findIdentityByEmail,
      channels: { email: channel },
    })
    const ghostElapsed = performance.now() - ghostStart

    expect(Math.abs(existsElapsed - ghostElapsed)).toBeLessThan(50)
  })

  it('channel.send throw -> signin.failed event with reason; no caller-side error', async () => {
    const failingChannel: Channel.Channel = {
      kind: 'email',
      id: 'failing',
      async send() {
        throw new Error('SMTP exploded')
      },
    }
    const { auth, adapter } = buildAuth()
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'a@x.com', email: 'a@x.com' }, providers: [] }),
      {},
    )
    const seen: string[] = []
    auth.events.on('signin.failed', (payload) => {
      seen.push(payload.reason)
    })

    const result = await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: async () => ({ id: ident.id }),
      channels: { email: failingChannel },
    })
    expect(result).toEqual({ ok: true })

    // Yield so the fire-and-forget chain settles.
    await new Promise((r) => setImmediate(r))
    expect(seen.length).toBeGreaterThanOrEqual(1)
    expect(seen[0]).toContain('channel.send threw')
    expect(seen[0]).toContain('SMTP exploded')
  })

  it('channel.send returning ok:false -> signin.failed event; no caller-side error', async () => {
    const rejecting: Channel.Channel = {
      kind: 'email',
      id: 'reject',
      async send() {
        return { ok: false, error: 'recipient blocked' }
      },
    }
    const { auth, adapter } = buildAuth()
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'a@x.com', email: 'a@x.com' }, providers: [] }),
      {},
    )
    const seen: string[] = []
    auth.events.on('signin.failed', (payload) => {
      seen.push(payload.reason)
    })

    const result = await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: async () => ({ id: ident.id }),
      channels: { email: rejecting },
    })
    expect(result).toEqual({ ok: true })

    await new Promise((r) => setImmediate(r))
    expect(seen).toContain('channel.send rejected delivery')
  })
})
