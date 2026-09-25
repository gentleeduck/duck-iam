/**
 * A stateless transport that authenticates a token and then refuses it has said something the store
 * cannot: the store is keyed by sid hash and holds no row for a token a transport minted, so the lookup
 * the engine falls through to always refuses with `no session for that sid`. That generic refusal used to
 * overwrite the specific one, and `AUTH_SESSION_EXPIRED` — raised only about a token whose signature
 * verified — never reached a caller through `resolveSession`, the path every server adapter takes.
 *
 * The fallthrough itself is the point of the branch and stays: a sid this transport cannot read belongs to
 * the store. Only the dated verdict outranks it.
 */
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { createAuth } from '~/core/config/config'
import { AuthError } from '~/core/errors'
import { CompositeTransport } from '~/core/transport/composite.transport'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { JwtTransport } from '~/core/transport/jwt.transport'
import type { Transport } from '~/core/transport/transport.types'
import { identityInput } from '~/test/store-inputs'
import type { Sessions } from '../../sessions'

const KEY = 'k'.repeat(64)
const SECOND = 1000

/** A guest session, which needs no identity row to resolve. */
const guest = (): Sessions.Me => ({
  aal: 1,
  absoluteExpiresAt: new Date(Date.now() + 600_000),
  actingAs: null,
  createdAt: new Date(),
  csrfHash: null,
  expiresAt: new Date(Date.now() + 60_000),
  factors: [],
  fingerprint: null,
  fresh: true,
  id: 's1',
  identityId: null,
  ip: null,
  kind: 'guest',
  rotatedAt: new Date(),
  tenantId: null,
  updatedAt: new Date(),
  userAgent: null,
})

const jwt = (ttlMs: number) =>
  new JwtTransport({
    issuer: 'iss',
    signKey: { key: KEY, kid: 'k1' },
    ttlMs,
    verifyKeys: [{ key: KEY, kid: 'k1' }],
  })

/** The token off the `issue` intents, which is where a host reads it from too. */
function mint(t: JwtTransport, session: Sessions.Me = guest()): string {
  const [intent] = t.issue('plain-sid', session, { absolute: false, fresh: true })
  const body = (intent as { body: { access_token: string } }).body
  return body.access_token
}

function build(transport: Transport.ITransport) {
  const adapter = new MemoryAdapter()
  const auth = createAuth({
    baseUrl: 'https://x.test',
    providers: [],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport,
  })
  return { adapter, auth }
}

const bearer = (token: string) => ({ headers: new Headers({ authorization: `Bearer ${token}` }) })

/** Run `fn` as though the clock had moved on by `ms`. */
async function later<T>(ms: number, fn: () => Promise<T>): Promise<T> {
  vi.useFakeTimers()
  try {
    vi.setSystemTime(new Date(Date.now() + ms))
    return await fn()
  } finally {
    vi.useRealTimers()
  }
}

describe('a transport verdict survives the store fallthrough', () => {
  it('answers the expiry, not the store refusal the fallthrough reaches', async () => {
    const t = jwt(SECOND)
    const { auth } = build(t)
    const req = bearer(mint(t))

    await later(5 * SECOND, async () => {
      await expect(auth.resolveSession(req)).rejects.toMatchObject({
        code: 'AUTH_SESSION_EXPIRED',
        meta: { expiredAt: expect.any(Number) },
      })
    })
  })

  it('names the same instant the transport named, rather than a fresh one', async () => {
    const t = jwt(SECOND)
    const { auth } = build(t)
    const token = mint(t)

    await later(5 * SECOND, async () => {
      const viaEngine = await auth.resolveSession(bearer(token)).wrap()
      const viaTransport = await t.verify(token).wrap()
      expect(viaEngine.error?.meta).toEqual(viaTransport.error?.meta)
    })
  })

  it('is still absence to a caller holding the readers, so it is a 401 and not a 500', async () => {
    const t = jwt(SECOND)
    const { auth } = build(t)
    const req = bearer(mint(t))

    await later(5 * SECOND, async () => {
      await expect(auth.resolveSession(req).orNull()).resolves.toBeNull()
    })
  })

  it('still resolves a live token, so the verdict is not raised over a good one', async () => {
    const t = jwt(60 * SECOND)
    const { auth } = build(t)

    const { data } = await auth.resolveSession(bearer(mint(t))).wrap()
    expect(data?.session.id).toBe('s1')
  })

  it('leaves the store to answer for a token the transport could not read', async () => {
    const { auth } = build(jwt(SECOND))

    // A refusal reached before any signature verified is "not a token of mine". Preferring it would
    // report `not a three-part JWS` for every signed-out cookie request.
    await expect(auth.resolveSession(bearer('not-a-jwt'))).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
      meta: { reason: 'no session for that sid' },
    })
  })

  it('keeps the fallthrough: a real sid the transport cannot read still resolves from the store', async () => {
    const { auth, adapter } = build(jwt(SECOND))
    const identity = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.test', username: 'a' }, providers: [] }),
    )
    const { sid } = await auth.sessions.create({ aal: 1, factors: [], identityId: identity.id, kind: 'user' })

    const { data } = await auth.resolveSession(bearer(sid)).wrap()
    expect(data?.identity?.id).toBe(identity.id)
  })

  it('rethrows a broken dependency at once rather than reading it as absence', async () => {
    const broken: Transport.ITransport = {
      extract: () => 'a-token',
      issue: () => [],
      revoke: () => [],
      verify: () => Promise.reject(new AuthError('AUTH_ADAPTER_FAILED')),
    }
    const { auth } = build(broken)

    // Not in the absent set, so it was never a fallthrough candidate and must not become one.
    await expect(auth.resolveSession({ headers: new Headers() })).rejects.toMatchObject({
      code: 'AUTH_ADAPTER_FAILED',
    })
  })
})

describe('a composite hands its members verdict up', () => {
  it('answers the expiry rather than "no transport vouched for the token"', async () => {
    const t = jwt(SECOND)
    const composite = new CompositeTransport([new CookieTransport(), t])
    const token = mint(t)

    await later(5 * SECOND, async () => {
      await expect(composite.verify(token)).rejects.toMatchObject({
        code: 'AUTH_SESSION_EXPIRED',
        meta: { expiredAt: expect.any(Number) },
      })
    })
  })

  it('carries it through the engine, which is the cookie-and-bearer deployment', async () => {
    const t = jwt(SECOND)
    const { auth } = build(new CompositeTransport([new CookieTransport(), t]))
    const req = bearer(mint(t))

    await later(5 * SECOND, async () => {
      await expect(auth.resolveSession(req)).rejects.toMatchObject({ code: 'AUTH_SESSION_EXPIRED' })
    })
  })

  it('still says nobody vouched when no member ever read the token', async () => {
    const composite = new CompositeTransport([new CookieTransport(), jwt(SECOND)])

    await expect(composite.verify('not-a-jwt')).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
      meta: { reason: 'no transport vouched for the token' },
    })
  })
})
