import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { AuthEngine } from '../../../core/engine'
import { AuthScryptHasher } from '../../../core/password/scrypt'
import { AuthCookieTransport } from '../../../core/transport/cookie'
import type { Channel } from '../../../core/types/infra'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { authMagicLink } from '../index'

interface MyProfile {
  email: string
}

function buildAuth(channel: Channel.IChannel): {
  auth: AuthEngine<MyProfile>
  adapter: MemoryAdapter<MyProfile>
} {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 50, windowMs: 60_000 }),
    passwords: { hasher: new AuthScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  auth.providers.register(
    authMagicLink<MyProfile>({
      channels: { email: channel },
      findIdentityByEmail: (email) => adapter.identities.findByEmail(email, {}),
      autoCreateIdentity: false,
      ttlMs: 60_000,
    }),
  )
  return { auth, adapter }
}

// A channel whose send() resolves only after `delayMs`. Used to
// simulate a real-world SMTP / SES network call.
function makeSlowChannel(delayMs: number): Channel.IChannel & { sendStarted: number } {
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

describe('magic-link.begin - timing-defense', () => {
  it('existing-identity branch returns BEFORE channel.send resolves (fire-and-forget)', async () => {
    const channel = makeSlowChannel(200) // 200 ms simulated SMTP
    const { auth, adapter } = buildAuth(channel)
    await adapter.identities.create({ profile: { email: 'a@x.com' }, providers: [] }, {})

    const start = performance.now()
    await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
    const elapsed = performance.now() - start
    // The handler returned in tens of ms (token mint + sha256 + upsert),
    // NOT after the 200 ms channel delay.
    expect(elapsed).toBeLessThan(100)
    // But channel.send WAS scheduled (fire-and-forget kicked off).
    expect(channel.sendStarted).toBe(1)
  })

  it('no-identity branch also returns fast - both branches have similar wall-clock time', async () => {
    const channel = makeSlowChannel(200)
    const { auth, adapter } = buildAuth(channel)
    await adapter.identities.create({ profile: { email: 'existing@x.com' }, providers: [] }, {})

    // Measure both branches.
    const existsStart = performance.now()
    await auth.flows.beginProvider('magic-link', { email: 'existing@x.com' })
    const existsElapsed = performance.now() - existsStart

    const ghostStart = performance.now()
    await auth.flows.beginProvider('magic-link', { email: 'ghost@x.com' })
    const ghostElapsed = performance.now() - ghostStart

    // The timing gap must be well below the 200 ms channel delay; the
    // fire-and-forget dispatch makes both branches return in ~ms.
    expect(Math.abs(existsElapsed - ghostElapsed)).toBeLessThan(50)
  })

  it('channel.send rejection does NOT crash the fire-and-forget - emits signin.failed', async () => {
    const failingChannel: Channel.IChannel = {
      kind: 'email',
      id: 'failing',
      async send() {
        throw new Error('SMTP exploded')
      },
    }
    const { auth, adapter } = buildAuth(failingChannel)
    await adapter.identities.create({ profile: { email: 'a@x.com' }, providers: [] }, {})

    const seen: string[] = []
    auth.events.on('signin.failed', (payload) => {
      seen.push(payload.reason)
    })

    // The call resolves with ok:true even though the channel threw.
    const intents = await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
    expect(intents).toEqual([{ type: 'json', status: 200, body: { ok: true } }])

    // Yield so the fire-and-forget chain can settle.
    await new Promise((r) => setImmediate(r))
    expect(seen).toHaveLength(1)
    expect(seen[0]).toContain('channel.send threw')
    expect(seen[0]).toContain('SMTP exploded')
  })

  it('channel.send returning ok:false emits signin.failed with the canonical reason', async () => {
    const rejectingChannel: Channel.IChannel = {
      kind: 'email',
      id: 'reject',
      async send() {
        return { ok: false, error: 'recipient quota exceeded' }
      },
    }
    const { auth, adapter } = buildAuth(rejectingChannel)
    await adapter.identities.create({ profile: { email: 'a@x.com' }, providers: [] }, {})

    const seen: string[] = []
    auth.events.on('signin.failed', (payload) => {
      seen.push(payload.reason)
    })

    await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })

    await new Promise((r) => setImmediate(r))
    expect(seen).toEqual(['channel.send rejected delivery'])
  })
})
