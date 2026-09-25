import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Deliver } from '~/core/flows/flows.delivery'
import type { Identities } from '~/core/identities/identities.types'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { identityInput } from '~/test/store-inputs'

interface MyProfile extends Identities.ProfileMetadataBase {
  email: string
}

function buildAuth(deliver: Deliver): { auth: AuthEngine<MyProfile>; adapter: MemoryAdapter<MyProfile> } {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    deliver,
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
  })
  return { auth, adapter }
}

function makeSlowChannel(delayMs: number): Deliver & { sendStarted: number } {
  const ch: Deliver & { sendStarted: number } = Object.assign(
    async (): Promise<void> => {
      ch.sendStarted++
      await new Promise((r) => setTimeout(r, delayMs))
    },
    { sendStarted: 0 },
  )
  return ch
}

describe('flows.requestPasswordReset - timing-defense', () => {
  it('existing-email branch returns BEFORE channel.send resolves (fire-and-forget)', async () => {
    const channel = makeSlowChannel(200)
    const { auth, adapter } = buildAuth(channel)
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'a@x.com', email: 'a@x.com' }, providers: [] }),
    )
    const findIdentityByEmail = async (): Promise<{ id: string } | null> => ({ id: ident.id })

    const start = performance.now()
    await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail,
    })
    const elapsed = performance.now() - start
    // The handler returned in tens of ms (token mint + create + hasTotp +
    // event emit), NOT after the 200 ms channel delay.
    expect(elapsed).toBeLessThan(100)
    // But channel.send WAS scheduled.
    expect(channel.sendStarted).toBe(1)
  })

  it('non-existing-email branch returns at the same wall-clock cost (within 50 ms)', async () => {
    const channel = makeSlowChannel(200)
    const { auth, adapter } = buildAuth(channel)
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'existing@x.com', email: 'existing@x.com' }, providers: [] }),
    )
    const findIdentityByEmail = async (email: string): Promise<{ id: string } | null> =>
      email === 'existing@x.com' ? { id: ident.id } : null

    const existsStart = performance.now()
    await auth.flows.requestPasswordReset({
      input: { email: 'existing@x.com' },
      findIdentityByEmail,
    })
    const existsElapsed = performance.now() - existsStart

    const ghostStart = performance.now()
    await auth.flows.requestPasswordReset({
      input: { email: 'ghost@x.com' },
      findIdentityByEmail,
    })
    const ghostElapsed = performance.now() - ghostStart

    expect(Math.abs(existsElapsed - ghostElapsed)).toBeLessThan(50)
  })

  it('a throwing deliver -> signin.failed event with reason; no caller-side error', async () => {
    const failingChannel: Deliver = async () => {
      throw new Error('SMTP exploded')
    }
    const { auth, adapter } = buildAuth(failingChannel)
    const ident = await adapter.identities.create(
      identityInput({ profile: { username: 'a@x.com', email: 'a@x.com' }, providers: [] }),
    )
    const seen: string[] = []
    auth.events.on('signin.failed', (payload) => {
      seen.push(payload.reason)
    })

    const result = await auth.flows.requestPasswordReset({
      input: { email: 'a@x.com' },
      findIdentityByEmail: async () => ({ id: ident.id }),
    })
    expect(result).toEqual({ ok: true })

    // Yield so the fire-and-forget chain settles.
    await new Promise((r) => setImmediate(r))
    expect(seen.length).toBeGreaterThanOrEqual(1)
    expect(seen[0]).toBe('deliver threw')
    expect(seen[0]).not.toContain('SMTP exploded')
  })
})
