import { describe, expect, it } from 'vitest'
import { FakeRedis } from '~/adapters/redis/redis-like'
import type { Sessions } from '~/core/sessions'
import { RedisEvents } from '../events.redis'

/**
 * A `Date` in an event payload only survives as long as the payload never
 * leaves the process. `emit` hands local handlers the original object, so every
 * existing test saw real Dates; the fan-out serialises through JSON, and the
 * subscriber on the other side used to get ISO strings wearing the payload's
 * types. Each test here therefore asserts on the REMOTE bus - the local one is
 * only ever a control.
 */
function twoBuses(): { local: RedisEvents; remote: RedisEvents } {
  const redis = new FakeRedis()
  return {
    local: new RedisEvents({ prefix: 'ev', redis }),
    remote: new RedisEvents({ prefix: 'ev', redis }),
  }
}

/** The lazy subscribe registers on a promise; let it land before emitting. */
const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 10))

function session(overrides: Partial<Sessions.Me> = {}): Sessions.Me {
  const now = new Date()
  return {
    absoluteExpiresAt: new Date(now.getTime() + 3_600_000),
    actingAs: null,
    aal: 1,
    createdAt: now,
    csrfHash: null,
    expiresAt: new Date(now.getTime() + 60_000),
    factors: [{ completedAt: now, method: 'password' }],
    fingerprint: null,
    fresh: true,
    id: 's1',
    identityId: 'i1',
    ip: null,
    kind: 'user',
    rotatedAt: now,
    tenantId: null,
    userAgent: null,
    ...overrides,
  }
}

describe('RedisEvents payload dates survive the fan-out', () => {
  it('a remote subscriber gets real Dates on the session, not the ISO strings JSON leaves behind', async () => {
    const { local, remote } = twoBuses()
    let seen: Sessions.Me | null = null
    remote.on('session.created', async (p) => {
      seen = p.session
    })
    await settle()

    await local.emit('session.created', { identity: null, session: session() })
    await settle()

    if (!seen) throw new Error('remote handler never ran')
    const got: Sessions.Me = seen
    expect(got.createdAt).toBeInstanceOf(Date)
    expect(got.expiresAt).toBeInstanceOf(Date)
    expect(got.rotatedAt).toBeInstanceOf(Date)
    expect(got.absoluteExpiresAt).toBeInstanceOf(Date)
    // Nested inside an array inside the payload - the case a shallow revive misses.
    expect(got.factors[0]?.completedAt).toBeInstanceOf(Date)
  })

  it('an impersonation window that closed still reads as closed on the far side', async () => {
    // This is the bug with teeth. `expiresAt < Date.now()` on a string compares
    // string-to-number and answers false, so a remote instance saw an expired
    // impersonation as live - and every audited event carries `actingAs`.
    const { local, remote } = twoBuses()
    const closed = new Date(Date.now() - 600_000)
    let expired: boolean | null = null
    remote.on('session.created', async (p) => {
      const at = p.session.actingAs
      expired = at ? at.expiresAt.getTime() < Date.now() : null
    })
    await settle()

    await local.emit('session.created', {
      identity: null,
      session: session({
        actingAs: {
          expiresAt: closed,
          realIdentityId: 'admin',
          reason: 'support',
          startedAt: new Date(Date.now() - 1_200_000),
        },
      }),
    })
    await settle()

    expect(expired).toBe(true)
  })

  it('leaves a free-text field holding a timestamp alone', async () => {
    // `reason` is not a date key, so it stays the string its type promises even
    // when a caller puts an ISO timestamp in it.
    const { local, remote } = twoBuses()
    let reason: unknown
    remote.on('session.created', async (p) => {
      reason = p.session.actingAs?.reason
    })
    await settle()

    await local.emit('session.created', {
      identity: null,
      session: session({
        actingAs: {
          expiresAt: new Date(Date.now() + 60_000),
          realIdentityId: 'admin',
          reason: '2026-01-01T00:00:00.000Z',
          startedAt: new Date(),
        },
      }),
    })
    await settle()

    expect(typeof reason).toBe('string')
  })

  it('leaves the caller-owned profile untouched, including keys that look like dates', async () => {
    // `profile` is the host app's own blob. A column it happens to call
    // `createdAt` is its business, and rewriting it into a Date would hand the
    // app back something it never stored.
    const { local, remote } = twoBuses()
    let profile: Record<string, unknown> | null = null
    remote.on('signup.completed', async (p) => {
      profile = p.identity.profile
    })
    await settle()

    await local.emit('signup.completed', {
      identity: {
        createdBy: null,
        updatedBy: null,
        createdAt: new Date(),
        deletedAt: null,
        deletedBy: null,
        emailVerified: false,
        id: 'i1',
        profile: {
          createdAt: '2026-01-01T00:00:00.000Z',
          email: 'a@x.com',
          expiresAt: 1_700_000_000_000,
          username: 'a',
        },
        providers: [{ addedAt: new Date(), providerId: 'google', providerSub: 'g1' }],
        updatedAt: new Date(),
        version: 1,
      },
    })
    await settle()

    if (!profile) throw new Error('remote handler never ran')
    const got: Record<string, unknown> = profile
    expect(typeof got.createdAt).toBe('string')
    expect(got.expiresAt).toBe(1_700_000_000_000)
  })

  it('revives a provider link addedAt, which lives in an array of objects', async () => {
    const { local, remote } = twoBuses()
    let addedAt: unknown
    remote.on('signup.completed', async (p) => {
      addedAt = p.identity.providers[0]?.addedAt
    })
    await settle()

    await local.emit('signup.completed', {
      identity: {
        createdBy: null,
        updatedBy: null,
        createdAt: new Date(),
        deletedAt: null,
        deletedBy: null,
        emailVerified: false,
        id: 'i1',
        profile: { email: 'a@x.com', username: 'a' },
        providers: [{ addedAt: new Date(), providerId: 'google', providerSub: 'g1' }],
        updatedAt: new Date(),
        version: 1,
      },
    })
    await settle()

    expect(addedAt).toBeInstanceOf(Date)
  })
})
