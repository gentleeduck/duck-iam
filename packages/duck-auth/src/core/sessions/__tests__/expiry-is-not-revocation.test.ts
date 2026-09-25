/**
 * `AUTH_SESSION_EXPIRED` is declared with a `{ expiredAt }` meta and exported in the
 * public union — and was raised by nothing. Every deadline in the package threw `AUTH_SESSION_REVOKED`
 * instead, whose meta is a free-text `reason` and which is also what a store answers for a row that is
 * absent, corrupt or another tenant's. A caller could not tell "your session timed out, sign in again"
 * from "your session was revoked", which are different words to the user and different alerts to an
 * operator.
 *
 * The code joins `ABSENT` in the same change, or round 23's property would break: `resolveSession(...)
 * .orNull()` is what every server adapter calls, and a code outside that set comes back a 500.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { ABSENT } from '~/core/answer'
import { sha256 } from '~/core/crypto'
import { InMemoryEvents } from '~/core/events'
import type { Sessions } from '~/core/sessions/sessions.types'
import { JwtTransport } from '~/core/transport/jwt.transport'
import { identityInput } from '~/test/store-inputs'
import { resolveBySid, SessionsImpl } from '../sessions'
import { DEFAULT_SESSION_CONFIG } from '../sessions.constants'

const DAY = 86_400_000

/** A session the JWT transport can serialise; only the deadlines matter here. */
function makeSession(): Sessions.Me {
  const now = Date.now()
  return {
    aal: 1,
    absoluteExpiresAt: new Date(now + DAY),
    actingAs: null,
    createdAt: new Date(now),
    csrfHash: null,
    expiresAt: new Date(now + DAY),
    factors: [{ completedAt: new Date(now), method: 'password' }],
    fingerprint: null,
    fresh: true,
    id: sha256('a-session'),
    identityId: 'u',
    ip: null,
    kind: 'user',
    rotatedAt: new Date(now),
    tenantId: null,
    updatedAt: new Date(now),
    userAgent: null,
  }
}

describe('a session that timed out says so, and is still absence', () => {
  let adapter: MemoryAdapter
  let facet: SessionsImpl
  let identityId: string

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    facet = new SessionsImpl(adapter.sessions, new InMemoryEvents(), DEFAULT_SESSION_CONFIG)
    identityId = (
      await adapter.identities.create(identityInput({ profile: { email: 'a@x.com', username: 'a' }, providers: [] }))
    ).id
  })

  /** A live session moved onto the given deadlines, with `createdAt` back a day to keep the row legal. */
  async function past(expiresAt: number, absoluteExpiresAt = Date.now() + DAY): Promise<string> {
    const { sid } = await facet.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId,
      kind: 'user',
    })
    await adapter.sessions.update(sha256(sid), {
      absoluteExpiresAt: new Date(absoluteExpiresAt),
      createdAt: new Date(Date.now() - DAY),
      expiresAt: new Date(expiresAt),
    })
    return sid
  }

  it('names the sliding deadline it fell past, rather than a free-text reason', async () => {
    const at = Date.now() - 1000
    const sid = await past(at)

    await expect(facet.getBySid(sid)).rejects.toMatchObject({
      code: 'AUTH_SESSION_EXPIRED',
      meta: { expiredAt: at },
    })
  })

  it('falls back to the absolute cap when the sliding deadline is the unreadable one', async () => {
    // A legal row cannot have its cap pass first — `absoluteExpiresAt >= expiresAt` is a constraint every
    // dialect carries — so the cap is the reported instant only when the sliding one says nothing.
    const at = Date.now() - 2000
    const sid = await past(Number.NaN, at)

    await expect(resolveBySid(sid, adapter.sessions, adapter.identities)).rejects.toMatchObject({
      code: 'AUTH_SESSION_EXPIRED',
      meta: { expiredAt: at },
    })
  })

  it('touch refuses it by the same code', async () => {
    const sid = await past(Date.now() - 1000)

    await expect(facet.touch(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
  })

  it('answers an instant even for a deadline nothing can read, which JSON would otherwise send as null', async () => {
    const before = Date.now()
    const sid = await past(Number.NaN, Number.NaN)

    const err = await facet.getBySid(sid).catch((e: { meta?: { expiredAt?: number } }) => e)
    const reported = (err as { meta: { expiredAt: number } }).meta.expiredAt
    expect(Number.isFinite(reported)).toBe(true)
    expect(reported).toBeGreaterThanOrEqual(before)
  })

  it('is in the absent set, so the reader every server adapter calls still answers null', async () => {
    const sid = await past(Date.now() - 1000)

    expect(ABSENT.has('AUTH_SESSION_EXPIRED')).toBe(true)
    await expect(facet.getBySid(sid).orNull()).resolves.toBeNull()
  })

  it('a revoked session is still the other code, which is the whole point of splitting them', async () => {
    const { sid } = await facet.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId,
      kind: 'user',
    })
    await facet.revoke(sid)

    await expect(facet.getBySid(sid)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it('a live session is refused by neither', async () => {
    const { sid } = await facet.create({
      aal: 1,
      factors: [{ completedAt: new Date(), method: 'password' }],
      identityId,
      kind: 'user',
    })

    await expect(facet.getBySid(sid)).resolves.toMatchObject({ identityId })
  })
})

describe('a JWT past its exp is the same answer', () => {
  const cfg = {
    issuer: 'https://app.test',
    signKey: { key: 'super-secret-key-for-tests-only', kid: 'k1' },
    verifyKeys: [{ key: 'super-secret-key-for-tests-only', kid: 'k1' }],
  }

  /** The token's own `exp` is the session's deadline where the transport is the session. */
  function expiredToken(ttlMs: number): { t: JwtTransport; token: string } {
    const t = new JwtTransport({ ...cfg, ttlMs })
    const intents = t.issue('plain-sid', makeSession(), { absolute: false, fresh: true })
    const json = intents.find((i) => i.type === 'json') as { body: { access_token: string } }
    return { t, token: json.body.access_token }
  }

  it('reports exp as the instant, in milliseconds', async () => {
    const { t, token } = expiredToken(-1)

    const err = await t.verify(token).catch((e: unknown) => e)
    expect(err).toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
    const reported = (err as { meta: { expiredAt: number } }).meta.expiredAt
    // Seconds on the wire, milliseconds in the meta, so a caller reads it against `Date.now()`.
    expect(reported % 1000).toBe(0)
    expect(reported).toBeLessThanOrEqual(Date.now())
  })

  it('a token that will not verify at all is its own code, neither expiry nor revocation', async () => {
    const t = new JwtTransport(cfg)

    await expect(t.verify('not.a.jwt')).rejects.toMatchObject({ code: 'AUTH_JWT_INVALID' })
  })

  it('a live token verifies', async () => {
    const { t, token } = expiredToken(60_000)

    await expect(t.verify(token)).resolves.toMatchObject({ identityId: 'u' })
  })
})
