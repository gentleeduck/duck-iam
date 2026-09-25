import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import { AuthEngine } from '~/core/engine'
import type { Deliver } from '~/core/flows/flows.delivery'
import { Identities } from '~/core/identities'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { identityInput } from '~/test/store-inputs'
import { magicLink } from '../index'

interface MyProfile extends Identities.ProfileMetadataBase {}

function buildAuth(channel: Deliver): {
  auth: AuthEngine<MyProfile>
  adapter: MemoryAdapter<MyProfile>
} {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app.example.com',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwords({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) })],
  })
  auth.providers.register(
    magicLink<MyProfile>({
      deliver: channel,
      findIdentityByEmail: (email) => orNull(adapter.identities.find({ email })),
      autoCreateIdentity: false,
      ttlMs: 60_000,
    }),
  )
  return { auth, adapter }
}

// A `deliver` that resolves only after `delayMs`, standing in for a real SMTP / SES network call.
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

// Records every store method the provider reaches for, so a branch that skips one is visible.
function recording<T extends object>(store: T, label: string, log: string[]): T {
  return new Proxy(store, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver)
      if (typeof value !== 'function') return value
      return (...args: unknown[]) => {
        log.push(`${label}.${String(prop)}`)
        return value.apply(target, args)
      }
    },
  })
}

describe('magic-link.begin - timing-defense', () => {
  it('existing-identity branch returns BEFORE channel.send resolves (fire-and-forget)', async () => {
    const channel = makeSlowChannel(200) // 200 ms simulated SMTP
    const { auth, adapter } = buildAuth(channel)
    await adapter.identities.create(identityInput({ profile: { email: 'a@x.com', username: 'a' }, providers: [] }))

    const start = performance.now()
    await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
    const elapsed = performance.now() - start
    // The handler returned in tens of ms (token mint + sha256 + create),
    // NOT after the 200 ms channel delay.
    expect(elapsed).toBeLessThan(100)
    // But channel.send WAS scheduled (fire-and-forget kicked off).
    expect(channel.sendStarted).toBe(1)
  })

  it('no-identity branch also returns fast - both branches have similar wall-clock time', async () => {
    const channel = makeSlowChannel(200)
    const { auth, adapter } = buildAuth(channel)
    await adapter.identities.create(
      identityInput({ profile: { email: 'existing@x.com', username: 'e' }, providers: [] }),
    )

    // Measure both branches.
    const existsStart = performance.now()
    await auth.flows.beginProvider('magic-link', { email: 'existing@x.com' })
    const existsElapsed = performance.now() - existsStart

    const ghostStart = performance.now()
    await auth.flows.beginProvider('magic-link', { email: 'ghost@x.com' })
    const ghostElapsed = performance.now() - ghostStart

    // Proves neither branch blocks on the channel, and nothing more: against the memory adapter a
    // skipped insert costs microseconds, so a 50 ms window cannot see store asymmetry. The call-count
    // test below is what does.
    expect(Math.abs(existsElapsed - ghostElapsed)).toBeLessThan(50)
  })

  it('both branches make the same store calls, in the same order', async () => {
    // Wall-clock cannot answer this one: the work an early return skips is a single indexed write,
    // invisible in memory and measurable only against a real database. Count the round trips instead.
    const log: string[] = []
    const channel = makeSlowChannel(0)
    const adapter = new MemoryAdapter<MyProfile>()
    const auth = new AuthEngine<MyProfile>({
      baseUrl: 'https://app.example.com',
      transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
      stores: {
        credentials: recording(adapter.credentials, 'credentials', log),
        identities: recording(adapter.identities, 'identities', log),
        sessions: adapter.sessions,
      },
      limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    })
    auth.providers.register(
      magicLink<MyProfile>({
        deliver: channel,
        findIdentityByEmail: (email) => orNull(adapter.identities.find({ email })),
        autoCreateIdentity: false,
        ttlMs: 60_000,
      }),
    )
    await adapter.identities.create(identityInput({ profile: { email: 'known@x.com', username: 'k' }, providers: [] }))

    log.length = 0
    await auth.flows.beginProvider('magic-link', { email: 'known@x.com' })
    const known = [...log]

    log.length = 0
    await auth.flows.beginProvider('magic-link', { email: 'ghost@x.com' })
    const ghost = [...log]

    expect(known.length).toBeGreaterThan(0)
    // Which store, not which method: the write has no decoy (`identity_id` is a foreign key), so the
    // unknown branch answers it with a read of the same table. The round trips must still line up.
    expect(ghost.map((c) => c.split('.')[0])).toEqual(known.map((c) => c.split('.')[0]))
  })

  it('a throwing deliver does NOT crash the fire-and-forget - emits signin.failed', async () => {
    const failingChannel: Deliver = async () => {
      throw new Error('SMTP exploded')
    }
    const { auth, adapter } = buildAuth(failingChannel)
    await adapter.identities.create(identityInput({ profile: { email: 'a@x.com', username: 'a' }, providers: [] }))

    const seen: string[] = []
    auth.events.on('signin.failed', (payload) => {
      seen.push(payload.reason)
    })

    // The call resolves with ok:true even though deliver threw.
    const intents = await auth.flows.beginProvider('magic-link', { email: 'a@x.com' })
    expect(intents).toEqual([{ type: 'json', status: 200, body: { ok: true } }])

    // Yield so the fire-and-forget chain can settle.
    await new Promise((r) => setImmediate(r))
    expect(seen).toHaveLength(1)
    // Fixed text: this flow's rendered body is the sign-in link, so the thrown message cannot go on the bus.
    expect(seen[0]).toBe('deliver threw')
    expect(seen[0]).not.toContain('SMTP exploded')
  })
})
