import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { orNull } from '~/core/answer'
import { createAuth } from '~/core/config/config'
import type { Adapter } from '../../../adapters/adapter'
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
  createdBy: null,
  updatedBy: null,
  id: 'i1',
  profile: { email: 'a@b.test', username: 'a' },
  providers: [],
  version: 1,
  emailVerified: true,
  createdAt: new Date(0),
  updatedAt: new Date(0),
  deletedAt: null,
  deletedBy: null,
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
  updatedAt: new Date(0),
  rotatedAt: new Date(0),
  expiresAt: new Date(Date.now() + 60_000),
  absoluteExpiresAt: new Date(Date.now() + 600_000),
  fresh: true,
  actingAs: null,
})

/** Every store method the code under test does not call. Throws rather than lying. */
const unexpected = (name: string) => () => Promise.reject(new Error(`unexpected call to ${name}()`))

/** A store answers the row or raises, so the doubles raise too - `orNull()` in the code under test is
 *  what turns that back into a value, and a double that returned null would not exercise it. */
function sessionStore(row: Sessions.Me | null) {
  const del = vi.fn(() => Promise.resolve(undefined))
  const getByHash = vi.fn(() =>
    row ? Promise.resolve(row) : Promise.reject(new AuthError('AUTH_SESSION_REVOKED', { reason: 'not found' })),
  )
  const store: Sessions.Store = {
    create: unexpected('sessions.create'),
    delete: del,
    deleteAllForIdentities: unexpected('sessions.deleteAllForIdentities'),
    deleteAllForIdentity: unexpected('sessions.deleteAllForIdentity'),
    deleteMany: unexpected('sessions.deleteMany'),
    gc: unexpected('sessions.gc'),
    getByHash,
    listByIdentity: unexpected('sessions.listByIdentity'),
    update: unexpected('sessions.update'),
  }
  return { del, getByHash, store }
}

function identityStore(row: Identities.Me | null | undefined) {
  const find = vi.fn(() => (row ? Promise.resolve(row) : Promise.reject(new AuthError('AUTH_IDENTITY_NOT_FOUND'))))
  const store: Identities.Store<Identities.ProfileMetadataBase> = {
    create: unexpected('identities.create'),
    erase: unexpected('identities.erase'),
    eraseMany: unexpected('identities.eraseMany'),
    find,
    gc: unexpected('identities.gc'),
    link: unexpected('identities.link'),
    restore: unexpected('identities.restore'),
    softDelete: unexpected('identities.softDelete'),
    softDeleteMany: unexpected('identities.softDeleteMany'),
    unlink: unexpected('identities.unlink'),
    update: unexpected('identities.update'),
  }
  return { find, store }
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

  return { engine, evaluate, find: identities.find, getByHash: sessions.getByHash, transport }
}

const PATHS = ['verify', 'sid'] as const
const SNAPSHOT: Anomaly.RequestSnapshot = { ip: '1.1.1.1', now: 0, userAgent: 'test' }
const req = { headers: new Headers() }

describe('resolveSession() revocation, on both resolution paths', () => {
  beforeEach(() => vi.clearAllMocks())

  it.each(PATHS)('%s: refuses a session whose identity was erased', async (path) => {
    const { engine } = makeEngine({ path, session: session('i1'), identity: null })

    await expect(resolveSession(engine, req)).rejects.toBeInstanceOf(AuthError)
    // SECURITY: its own code, outside the absent set, so `orNull()` at a framework adapter cannot read a
    // session that outlived its identity as a plain sign-out.
    await expect(resolveSession(engine, req)).rejects.toMatchObject({ code: 'AUTH_SESSION_IDENTITY_ERASED' })
  })

  /** `find` returning undefined rather than null is the same erasure. */
  it.each(PATHS)('%s: an undefined identity is refused, not just a null one', async (path) => {
    const { engine } = makeEngine({ path, session: session('i1'), identity: undefined })
    await expect(resolveSession(engine, req)).rejects.toMatchObject({ code: 'AUTH_SESSION_IDENTITY_ERASED' })
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
    expect(result.session.identityId).toBeNull()
  })

  it.each(PATHS)('%s: a guest session never looks an identity up at all', async (path) => {
    const { engine, find } = makeEngine({ path, session: session(null), identity: null })
    await resolveSession(engine, req)
    expect(find).not.toHaveBeenCalled()
  })

  /** Tenant before identity, on both paths: a foreign token looks absent rather than erased. */
  it.each(PATHS)('%s: a cross-tenant token with an erased identity is refused as absent', async (path) => {
    const { engine } = makeEngine({ path, session: session('i1', 'tenant-a'), identity: null })
    // The absent code, not the erasure one: a foreign tenant must not learn that the identity is gone.
    await expect(resolveSession(engine, req, { expectedTenantId: 'tenant-b' })).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })
  })

  it.each(PATHS)('%s: a cross-tenant token never looks the identity up at all', async (path) => {
    const { engine, find } = makeEngine({ path, session: session('i1', 'tenant-a'), identity: null })
    await expect(resolveSession(engine, req, { expectedTenantId: 'tenant-b' })).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })
    expect(find).not.toHaveBeenCalled()
  })

  it.each(PATHS)('%s: a cross-tenant token with a live identity is refused as absent', async (path) => {
    const { engine } = makeEngine({ path, session: session('i1', 'tenant-a'), identity: LIVE })
    await expect(resolveSession(engine, req, { expectedTenantId: 'tenant-b' })).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
    })
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
      code: 'AUTH_SESSION_IDENTITY_ERASED',
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

  it('no token is refused without touching either store', async () => {
    const { engine, find, getByHash, transport } = makeEngine({
      path: 'sid',
      session: session('i1'),
      identity: null,
    })
    transport.extract.mockReturnValue(null)

    await expect(resolveSession(engine, req)).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
      meta: { reason: 'the request carries no transport token' },
    })
    expect(find).not.toHaveBeenCalled()
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

    await expect(resolveSession(engine, req)).rejects.toMatchObject({ code: 'AUTH_SESSION_IDENTITY_ERASED' })
    expect(getByHash).toHaveBeenCalled()
  })

  it('an expired session is absence on the sid path, not the erasure code', async () => {
    const expired = { ...session('i1'), expiresAt: new Date(Date.now() - 1000) }
    const { engine, getByHash } = makeEngine({ path: 'sid', session: expired, identity: null })

    // Deadline before identity, so an expired session whose identity is also gone reads as expired.
    await expect(resolveSession(engine, req)).rejects.toMatchObject({
      code: 'AUTH_SESSION_EXPIRED',
      meta: { expiredAt: expect.any(Number) },
    })
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
      return { find: identities.find, identities: identities.store, sessions: sessions.store }
    }

    it('refuses an erased identity without help from the caller', async () => {
      const { sessions, identities } = stores(session('i1'), null)
      await expect(resolveBySid('sid', sessions, identities)).rejects.toMatchObject({
        code: 'AUTH_SESSION_IDENTITY_ERASED',
      })
    })

    it('returns a guest session rather than refusing it', async () => {
      const { sessions, identities } = stores(session(null), null)
      await expect(resolveBySid('sid', sessions, identities)).resolves.toMatchObject({ identity: null })
    })

    it('refuses a foreign tenant as absent, before looking the identity up', async () => {
      const { sessions, identities, find } = stores(session('i1', 'tenant-a'), null)
      await expect(resolveBySid('sid', sessions, identities, { expectedTenantId: 'tenant-b' })).rejects.toMatchObject({
        code: 'AUTH_SESSION_REVOKED',
        meta: { reason: 'the session belongs to another tenant' },
      })
      expect(find).not.toHaveBeenCalled()
    })
  })

  it('both paths produce the same verdict for the same inputs', async () => {
    const verdict = async (path: (typeof PATHS)[number], identity: Identities.Me | null, identityId: string | null) => {
      const { engine } = makeEngine({ path, session: session(identityId), identity })
      try {
        const r = await resolveSession(engine, req)
        return `identity:${r.identity === null ? 'null' : 'live'}`
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

/**
 * The readers belong to the engine method, not to the free function above, and which refusals they take is
 * the whole contract: a caller writes `.orNull()` once and every framework adapter ships it.
 */
describe('AuthEngine.resolveSession readers', () => {
  const buildAuth = () => {
    const adapter = new MemoryAdapter()
    const auth = createAuth({
      baseUrl: 'https://x.test',
      providers: [],
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    })
    return { adapter, auth }
  }
  const cookie = (sid: string) => ({ headers: new Headers({ cookie: `duck-sid=${sid}` }) })

  it('rejects an unauthenticated request, and orNull reads that back as null', async () => {
    const { auth } = buildAuth()
    const bare = { headers: new Headers() }

    await expect(auth.resolveSession(bare)).rejects.toMatchObject({
      code: 'AUTH_SESSION_REVOKED',
      meta: { reason: 'the request carries no transport token' },
    })
    await expect(auth.resolveSession(bare).orNull()).resolves.toBeNull()
  })

  it('resolves the (session, identity) pair for a live cookie', async () => {
    const { adapter, auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@b.test', username: 'a' } })
    const { sid } = await auth.sessions.create({ aal: 1, factors: [], identityId: identity.id, kind: 'user' })

    await expect(auth.resolveSession(cookie(sid))).resolves.toMatchObject({ identity: { id: identity.id } })
  })

  /**
   * SECURITY: the regression guard for the split. Absence and "this session outlived its identity" used to
   * share `AUTH_SESSION_REVOKED`, so putting `.orNull()` on the sixteen framework call sites would have
   * turned a data-integrity violation into an ordinary signed-out response at every one of them.
   */
  it('does not let orNull swallow a session whose identity was erased', async () => {
    const { adapter, auth } = buildAuth()
    const identity = await auth.identities.create({ profile: { email: 'a@b.test', username: 'a' } })
    const { sid } = await auth.sessions.create({ aal: 1, factors: [], identityId: identity.id, kind: 'user' })
    // Dropped on its own, leaving the session behind: the schema without the cascade, or the window
    // between the identity delete and the session cleanup.
    adapter.raw.identities.delete(identity.id)

    await expect(auth.resolveSession(cookie(sid))).rejects.toMatchObject({ code: 'AUTH_SESSION_IDENTITY_ERASED' })
    await expect(auth.resolveSession(cookie(sid)).orNull()).rejects.toMatchObject({
      code: 'AUTH_SESSION_IDENTITY_ERASED',
    })
    await expect(auth.resolveSession(cookie(sid)).orDefault({ identity: null, session: {} as never })).rejects.toThrow()
  })

  it('wrap() hands the refusal back as a value rather than throwing it', async () => {
    const { auth } = buildAuth()
    const { data, error } = await auth.resolveSession({ headers: new Headers() }).wrap()

    expect(data).toBeNull()
    expect(error).toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })
})
