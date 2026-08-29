import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Anomaly } from '../../anomaly/anomaly.types'
import { AuthError } from '../../errors'
import type { Identities } from '../../identities'
import type { Sessions } from '../../sessions'
import { resolveBySid } from '../../sessions'
import { resolveSession } from '../engine.resolve-session'

/**
 * Every case runs against both resolution paths from one table. A suite covering only
 * the sid path passes now and still passes once someone adds a verifying transport,
 * which is how the two came to disagree unnoticed.
 */
const LIVE: Identities.Me = {
  id: 'i1',
  profile: { email: 'a@b.test', username: 'a' },
  providers: [],
  version: 1,
  emailVerified: true,
  createdAt: new Date(0),
  updatedAt: new Date(0),
  deletedAt: null,
}

const session = (identityId: string | null, tenantId: string | null = null): Sessions.Me => ({
  id: 's1',
  identityId,
  tenantId,
  kind: 'user',
  aal: 1,
  factors: [],
  csrfHash: null,
  ip: null,
  userAgent: null,
  fingerprint: null,
  createdAt: new Date(0),
  rotatedAt: new Date(0),
  expiresAt: new Date(Date.now() + 60_000),
  absoluteExpiresAt: new Date(Date.now() + 600_000),
  fresh: true,
  actingAs: null,
})

/** Every store method the code under test does not call. Throws rather than lying. */
const unexpected = (name: string) => () => Promise.reject(new Error(`unexpected call to ${name}()`))

function sessionStore(row: Sessions.Me | null) {
  const del = vi.fn(async () => undefined)
  const getByHash = vi.fn(async () => row)
  const store: Sessions.Store = {
    create: unexpected('sessions.create'),
    delete: del,
    deleteAllForIdentity: unexpected('sessions.deleteAllForIdentity'),
    gc: unexpected('sessions.gc'),
    getByHash,
    listByIdentity: unexpected('sessions.listByIdentity'),
    update: unexpected('sessions.update'),
  }
  return { del, getByHash, store }
}

function identityStore(row: Identities.Me | null | undefined) {
  const findById = vi.fn(async () => row as Identities.Me | null)
  const store: Identities.Store<Identities.ProfileMetadataBase> = {
    create: unexpected('identities.create'),
    erase: unexpected('identities.erase'),
    findByEmail: unexpected('identities.findByEmail'),
    findById,
    findByProviderSub: unexpected('identities.findByProviderSub'),
    link: unexpected('identities.link'),
    merge: unexpected('identities.merge'),
    restore: unexpected('identities.restore'),
    softDelete: unexpected('identities.softDelete'),
    unlink: unexpected('identities.unlink'),
    update: unexpected('identities.update'),
  }
  return { findById, store }
}

type Engine = Parameters<typeof resolveSession>[0]

/** Builds an engine whose only difference is which resolution path it takes. */
function makeEngine(opts: {
  path: 'verify' | 'sid'
  session: Sessions.Me | null
  identity: Identities.Me | null | undefined
  detectors?: string[]
}) {
  const identities = identityStore(opts.identity)
  const sessions = sessionStore(opts.session)
  const evaluate = vi.fn(async () => ({ risk: 'low' }))

  const transport = {
    extract: vi.fn(() => 'a-token' as string | null),
    ...(opts.path === 'verify' && { verify: vi.fn(async () => opts.session) }),
  }

  const engine = {
    anomaly: { evaluate, list: vi.fn(() => opts.detectors ?? []) },
    cfg: { stores: { identities: identities.store, sessions: sessions.store } },
    transport,
  } as unknown as Engine

  return { engine, evaluate, findById: identities.findById, getByHash: sessions.getByHash, transport }
}

const PATHS = ['verify', 'sid'] as const
const SNAPSHOT: Anomaly.RequestSnapshot = { ip: '1.1.1.1', now: 0, userAgent: 'test' }
const req = { headers: new Headers() }

describe('resolveSession() revocation, on both resolution paths', () => {
  beforeEach(() => vi.clearAllMocks())

  it.each(PATHS)('%s: refuses a session whose identity was erased', async (path) => {
    const { engine } = makeEngine({ path, session: session('i1'), identity: null })

    await expect(resolveSession(engine, req)).rejects.toBeInstanceOf(AuthError)
    await expect(resolveSession(engine, req)).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
      meta: { reason: 'identity-erased' },
    })
  })

  /** `findById` returning undefined rather than null is the same erasure. */
  it.each(PATHS)('%s: an undefined identity is refused, not just a null one', async (path) => {
    const { engine } = makeEngine({ path, session: session('i1'), identity: undefined })
    await expect(resolveSession(engine, req)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })

  it.each(PATHS)('%s: resolves normally when the identity is live', async (path) => {
    const { engine } = makeEngine({ path, session: session('i1'), identity: LIVE })
    await expect(resolveSession(engine, req)).resolves.toMatchObject({ identity: LIVE })
  })

  /** `createGuest` mints `identityId: null`, so refusing that would log out every guest. */
  it.each(PATHS)('%s: a guest session carries no identity and is still valid', async (path) => {
    const { engine } = makeEngine({ path, session: session(null), identity: null })
    const result = await resolveSession(engine, req)
    expect(result).toMatchObject({ identity: null })
    expect(result?.session.identityId).toBeNull()
  })

  it.each(PATHS)('%s: a guest session never looks an identity up at all', async (path) => {
    const { engine, findById } = makeEngine({ path, session: session(null), identity: null })
    await resolveSession(engine, req)
    expect(findById).not.toHaveBeenCalled()
  })

  /** Tenant before identity, on both paths: a foreign token looks absent rather than erased. */
  it.each(PATHS)('%s: a cross-tenant token with an erased identity returns null', async (path) => {
    const { engine } = makeEngine({ path, session: session('i1', 'tenant-a'), identity: null })
    await expect(resolveSession(engine, req, { expectedTenantId: 'tenant-b' })).resolves.toBeNull()
  })

  it.each(PATHS)('%s: a cross-tenant token never looks the identity up at all', async (path) => {
    const { engine, findById } = makeEngine({ path, session: session('i1', 'tenant-a'), identity: null })
    await resolveSession(engine, req, { expectedTenantId: 'tenant-b' })
    expect(findById).not.toHaveBeenCalled()
  })

  it.each(PATHS)('%s: a cross-tenant token with a live identity returns null', async (path) => {
    const { engine } = makeEngine({ path, session: session('i1', 'tenant-a'), identity: LIVE })
    await expect(resolveSession(engine, req, { expectedTenantId: 'tenant-b' })).resolves.toBeNull()
  })

  /** Detectors take the identity, so an erased one must be refused before they run. */
  it.each(PATHS)('%s: an erased identity never reaches an anomaly detector', async (path) => {
    const { engine, evaluate } = makeEngine({
      path,
      session: session('i1'),
      identity: null,
      detectors: ['impossible-travel'],
    })

    await expect(resolveSession(engine, req, { requestSnapshot: SNAPSHOT })).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })
    expect(evaluate).not.toHaveBeenCalled()
  })

  it.each(PATHS)('%s: a live identity still reaches the detectors', async (path) => {
    const { engine } = makeEngine({
      path,
      session: session('i1'),
      identity: LIVE,
      detectors: ['impossible-travel'],
    })

    const result = await resolveSession(engine, req, { requestSnapshot: SNAPSHOT })
    expect(result).toMatchObject({ anomaly: { risk: 'low' } })
  })

  /** Falsy, so it reads as a guest. A data bug the guard cannot tell from one, pinned as-is. */
  it.each(PATHS)('%s: an empty identityId is treated as a guest, not an erasure', async (path) => {
    const { engine } = makeEngine({ path, session: session(''), identity: null })
    await expect(resolveSession(engine, req)).resolves.toMatchObject({ identity: null })
  })

  it('no token resolves to null without touching either store', async () => {
    const { engine, findById, getByHash, transport } = makeEngine({
      path: 'sid',
      session: session('i1'),
      identity: null,
    })
    transport.extract.mockReturnValue(null)

    await expect(resolveSession(engine, req)).resolves.toBeNull()
    expect(findById).not.toHaveBeenCalled()
    expect(getByHash).not.toHaveBeenCalled()
  })

  /**
   * A transport that declares `verify` but cannot read this token falls through to the
   * sid path. compositeTransport does exactly this when no child verifies, which is the
   * only reason the weaker path was never taken in production.
   */
  it('a verify that returns null falls through to the sid path, which still refuses', async () => {
    const { engine, getByHash, transport } = makeEngine({ path: 'verify', session: session('i1'), identity: null })
    transport.verify?.mockResolvedValue(null)

    await expect(resolveSession(engine, req)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    expect(getByHash).toHaveBeenCalled()
  })

  it('an expired session is null on the sid path, not a revocation error', async () => {
    const expired = { ...session('i1'), expiresAt: new Date(Date.now() - 1000) }
    const { engine, getByHash } = makeEngine({ path: 'sid', session: expired, identity: null })

    await expect(resolveSession(engine, req)).resolves.toBeNull()
    expect(getByHash).toHaveBeenCalled()
  })

  /**
   * `resolveBySid` is exported, so it has to refuse on its own rather than lean on
   * `finalize`. Through `resolveSession` the two are indistinguishable, which is why
   * this asserts the function directly.
   */
  describe('resolveBySid, called directly', () => {
    const stores = (row: Sessions.Me | null, identity: Identities.Me | null) => {
      const identities = identityStore(identity)
      const sessions = sessionStore(row)
      return { findById: identities.findById, identities: identities.store, sessions: sessions.store }
    }

    it('refuses an erased identity without help from the caller', async () => {
      const { sessions, identities } = stores(session('i1'), null)
      await expect(resolveBySid('sid', sessions, identities)).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
      })
    })

    it('returns a guest session rather than refusing it', async () => {
      const { sessions, identities } = stores(session(null), null)
      await expect(resolveBySid('sid', sessions, identities)).resolves.toMatchObject({ identity: null })
    })

    it('returns null for a foreign tenant, before looking the identity up', async () => {
      const { sessions, identities, findById } = stores(session('i1', 'tenant-a'), null)
      await expect(resolveBySid('sid', sessions, identities, { expectedTenantId: 'tenant-b' })).resolves.toBeNull()
      expect(findById).not.toHaveBeenCalled()
    })
  })

  it('both paths produce the same verdict for the same inputs', async () => {
    const verdict = async (path: (typeof PATHS)[number], identity: Identities.Me | null, identityId: string | null) => {
      const { engine } = makeEngine({ path, session: session(identityId), identity })
      try {
        const r = await resolveSession(engine, req)
        return r === null ? 'null' : `identity:${r.identity === null ? 'null' : 'live'}`
      } catch (e) {
        return `throw:${(e as AuthError).code}`
      }
    }

    for (const [identity, identityId] of [
      [null, 'i1'],
      [LIVE, 'i1'],
      [null, null],
    ] as const) {
      expect(await verdict('verify', identity, identityId)).toBe(await verdict('sid', identity, identityId))
    }
  })
})
