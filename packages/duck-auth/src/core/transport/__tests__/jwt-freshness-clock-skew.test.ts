import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Sessions } from '~/core/sessions/sessions.types'
import { MemoryLimiter } from '~/limiters/memory'
import { CookieTransport } from '../cookie.transport'
import { JwtTransport } from '../jwt.transport'

const FRESHNESS_MS = 5 * 60 * 1000

function fakeSession(overrides: Partial<Sessions.Me> = {}): Sessions.Me {
  const now = Date.now()
  return {
    aal: 2,
    absoluteExpiresAt: new Date(now + 3_600_000),
    actingAs: null,
    createdAt: new Date(now),
    updatedAt: new Date(now),
    csrfHash: null,
    expiresAt: new Date(now + 3_600_000),
    factors: [
      { completedAt: new Date(now), method: 'password' },
      { completedAt: new Date(now), method: 'totp' },
    ],
    fingerprint: null,
    fresh: true,
    id: 'row-hash',
    identityId: 'user-1',
    ip: null,
    kind: 'user',
    rotatedAt: new Date(now),
    tenantId: null,
    userAgent: null,
    ...overrides,
  }
}

function accessToken(intents: ReturnType<JwtTransport['issue']>): string {
  const json = intents.find((i) => i.type === 'json')
  return (json as { body: { access_token: string } }).body.access_token
}

/**
 * `frsh` is minted from the issuing server's clock and read against the verifying server's. Nothing
 * makes those the same clock, and both freshness gates subtracted in one direction only.
 */
describe('freshness is bounded in both directions', () => {
  const cfg = {
    freshnessMs: FRESHNESS_MS,
    issuer: 'https://app.example.com',
    signKey: { kid: 'k1', key: 'super-secret-key-for-tests-only' },
    ttlMs: 3_600_000,
    verifyKeys: [{ kid: 'k1', key: 'super-secret-key-for-tests-only' }],
  }

  it('a rotatedAt far in the future does not read as fresh', async () => {
    const t = new JwtTransport(cfg)
    const skewed = fakeSession({ rotatedAt: new Date(Date.now() + 60 * 60 * 1000) })
    const back = await t.verify(accessToken(t.issue('plain-sid', skewed, { absolute: false, fresh: true })))
    expect(back).not.toBeNull()
    expect(back?.fresh).toBe(false)
  })

  it('a rotatedAt inside the window still reads as fresh', async () => {
    const t = new JwtTransport(cfg)
    const back = await t.verify(accessToken(t.issue('plain-sid', fakeSession(), { absolute: false, fresh: true })))
    expect(back?.fresh).toBe(true)
  })

  it('checkStepUp does not accept a rotatedAt far in the future as recent', async () => {
    const adapter = new MemoryAdapter()
    const auth = new AuthEngine({
      baseUrl: 'https://app.example.com',
      limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
      stores: {
        credentials: adapter.credentials,
        identities: adapter.identities,
        sessions: adapter.sessions,
      },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    const skewed = fakeSession({ rotatedAt: new Date(Date.now() + 60 * 60 * 1000) })
    const r = await auth.flows.checkStepUp(skewed, { aal: 2, freshness: FRESHNESS_MS })
    expect(r.satisfied).toBe(false)
    if (!r.satisfied) expect(r.reason).toBe('fresh-required')
  })
})
