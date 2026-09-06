import { beforeEach, describe, expect, it } from 'vitest'
import type { Credential } from '~/core/credentials/credentials.types'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import { credentialInput, identityInput, sessionInput } from '~/test/store-inputs'
import { createSqlStores } from '../index'
import type { SqlBridge } from '../sql.types'

type ProfileShape = {
  username: string
  email: string
  name?: string
}

/**
 * Pure in-memory `SqlBridge` for tests. Mirrors the rowwise contract a
 * real ORM impl would expose. Sufficient to exercise the wrapper logic
 * (JSON encode/decode, tenant scoping, optimistic version, null vs
 * undefined coercion) without spinning up Postgres.
 */
function makeInMemoryBridge(): SqlBridge.Me<ProfileShape> {
  const identities = new Map<string, Identities.Me<ProfileShape>>()
  const credentials = new Map<string, Credential.Me>()
  const sessions = new Map<string, Sessions.Me>()

  return {
    identities: {
      findById: async (id) => {
        const r = identities.get(id)
        if (!r) return null
        return r
      },
      findByEmail: async (email) => {
        for (const r of identities.values()) {
          const profile = r.profile as { email?: string } | null
          if (profile?.email === email) return r
        }
        return null
      },
      findByProviderSub: async (providerId, sub) => {
        for (const r of identities.values()) {
          if (r.providers.some((l) => l.providerId === providerId && l.providerSub === sub)) return r
        }
        return null
      },
      insert: async (row) => {
        identities.set(row.id, row)
      },
      updateConditional: async (id, patch, expectedVersion) => {
        const cur = identities.get(id)
        if (!cur || cur.version !== expectedVersion) return null
        const next = { ...cur, ...patch } as Identities.Me<ProfileShape>
        identities.set(id, next)
        return next
      },
      softDelete: async (id, deletedAt) => {
        const cur = identities.get(id)
        if (!cur) return null
        const next = { ...cur, deletedAt, emailVerified: false }
        identities.set(id, next)
        return next
      },
      restore: async (id) => {
        const cur = identities.get(id)
        if (!cur) return null
        const next = { ...cur, deletedAt: null }
        identities.set(id, next)
        return next
      },
      erase: async (id) => {
        const cur = identities.get(id) ?? null
        identities.delete(id)
        return cur
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt) => {
        const cur = identities.get(identityId)
        if (!cur) return null
        const next = { ...cur, providers: [...cur.providers, { providerId, providerSub, addedAt }] }
        identities.set(identityId, next)
        return next
      },
      deleteProviderLink: async (identityId, providerId) => {
        const cur = identities.get(identityId)
        if (!cur) return null
        const next = { ...cur, providers: cur.providers.filter((l) => l.providerId !== providerId) }
        identities.set(identityId, next)
        return next
      },
      merge: async (survivorId, dupId) => {
        for (const c of credentials.values()) {
          if (c.identityId === dupId) c.identityId = survivorId
        }
        for (const s of sessions.values()) {
          if (s.identityId === dupId) s.identityId = survivorId
        }
        identities.delete(dupId)
        return identities.get(survivorId) ?? null
      },
    },
    credentials: {
      findById: async (id) => credentials.get(id) ?? null,
      listByIdentity: async (identityId, kind) =>
        [...credentials.values()].filter((r) => r.identityId === identityId && (kind === undefined || r.kind === kind)),
      findByProviderSub: async (provider, sub) => {
        for (const r of credentials.values()) {
          const meta = r.metadata as { provider?: string; sub?: string } | null
          if (meta?.provider === provider && meta.sub === sub) return r
        }
        return null
      },
      findByHashedSecret: async (secretHash, kind, tenantId) => {
        for (const r of credentials.values()) {
          if (r.kind !== kind || r.secret !== secretHash) continue
          // Match SQL bridge contract: undefined tid = global; set tid
          // requires exact match OR row.tenantId === null (global rows).
          if (tenantId !== undefined && r.tenantId !== tenantId && r.tenantId !== null) continue
          return r
        }
        return null
      },
      insert: async (row) => {
        credentials.set(row.id, row)
      },
      updateConditional: async (id, patch, expectedVersion) => {
        const cur = credentials.get(id)
        if (!cur || cur.version !== expectedVersion) return null
        const next = { ...cur, ...patch } as Credential.Me
        credentials.set(id, next)
        return next
      },
      revoke: async (id, revokedAt) => {
        const cur = credentials.get(id)
        if (!cur) return null
        const next = { ...cur, revokedAt: new Date(revokedAt) }
        credentials.set(id, next)
        return next
      },
      delete: async (id) => {
        const cur = credentials.get(id) ?? null
        credentials.delete(id)
        return cur
      },
      deleteByKind: async (identityId, kind) => {
        const removed: Credential.Me[] = []
        for (const [id, r] of credentials) {
          if (r.identityId === identityId && r.kind === kind) {
            removed.push(r)
            credentials.delete(id)
          }
        }
        return removed
      },
    },
    sessions: {
      insert: async (row) => {
        sessions.set(row.id, row)
      },
      findByHash: async (sidHash) => sessions.get(sidHash) ?? null,
      update: async (id, patch) => {
        const cur = sessions.get(id)
        if (!cur) return null
        const next = { ...cur, ...patch } as Sessions.Me
        sessions.set(id, next)
        return next
      },
      delete: async (id) => {
        sessions.delete(id)
      },
      listByIdentity: async (identityId) => [...sessions.values()].filter((s) => s.identityId === identityId),
      deleteAllForIdentity: async (identityId) => {
        for (const [id, s] of sessions) {
          if (s.identityId === identityId) sessions.delete(id)
        }
      },
      deleteExpired: async (now) => {
        let deleted = 0
        for (const [id, s] of sessions) {
          if (s.absoluteExpiresAt.getTime() < now.getTime()) {
            sessions.delete(id)
            deleted++
          }
        }
        return deleted
      },
    },
  }
}

describe('authCreateSqlStores', () => {
  let bridge: SqlBridge.Me<ProfileShape>
  let stores: ReturnType<typeof createSqlStores<ProfileShape>>

  beforeEach(() => {
    bridge = makeInMemoryBridge()
    stores = createSqlStores<ProfileShape>(bridge)
  })

  it('identities.create -> findById round-trips the profile JSON encoded', async () => {
    const ident = await stores.identities.create(
      identityInput({ profile: { username: 'a@b.com', email: 'a@b.com', name: 'A' }, providers: [] }),
    )
    expect(ident.id).toBeTruthy()
    const fetched = await stores.identities.findById(ident.id)
    expect(fetched?.profile?.email).toBe('a@b.com')
    expect(fetched?.profile?.name).toBe('A')
  })

  it('identities.findByEmail decodes the JSON profile', async () => {
    await stores.identities.create(identityInput({ profile: { username: 'x@y.com', email: 'x@y.com' }, providers: [] }))
    const found = await stores.identities.findByEmail('x@y.com')
    expect(found?.profile?.email).toBe('x@y.com')
  })

  it('identities.update bumps version + rejects stale writes', async () => {
    const ident = await stores.identities.create(
      identityInput({ profile: { username: 'a@b.com', email: 'a@b.com' }, providers: [] }),
    )
    const v2 = await stores.identities.update(ident.id, { profile: { username: 'b@b.com', email: 'b@b.com' } }, 1)
    expect(v2.version).toBe(2)
    expect(v2.profile?.email).toBe('b@b.com')
    await expect(
      stores.identities.update(ident.id, { profile: { username: 'c@b.com', email: 'c@b.com' } }, 1),
    ).rejects.toMatchObject({
      code: 'AUTH_STALE_WRITE',
    })
  })

  it('credentials.upsert + findByHashedSecret round-trips secret + metadata', async () => {
    const ident = await stores.identities.create(
      identityInput({ profile: { username: 'a@b.com', email: 'a@b.com' }, providers: [] }),
    )
    await stores.credentials.upsert(
      credentialInput({ identityId: ident.id, kind: 'password', secret: 'hash:xyz', metadata: { strength: 0.9 } }),
      {},
    )
    const found = await stores.credentials.findByHashedSecret('hash:xyz', 'password', {})
    expect(found?.identityId).toBe(ident.id)
    expect((found?.metadata as { strength: number }).strength).toBe(0.9)
  })

  it('credentials.rotate bumps version', async () => {
    const ident = await stores.identities.create(
      identityInput({ profile: { username: 'a@b.com', email: 'a@b.com' }, providers: [] }),
    )
    const cred = await stores.credentials.upsert(
      credentialInput({ identityId: ident.id, kind: 'password', secret: 's1' }),
      {},
    )
    const rotated = await stores.credentials.rotate(cred.id, 's2', cred.version, {})
    expect(rotated.secret).toBe('s2')
    expect(rotated.version).toBe(cred.version + 1)
  })

  it('sessions.create -> getByHash round-trips factors + actingAs JSON', async () => {
    const now = Date.now()
    await stores.sessions.create(
      sessionInput({
        id: 'h1',
        identityId: 'i1',
        kind: 'user',
        aal: 2,
        factors: [{ method: 'password', completedAt: new Date(now) }],
        createdAt: new Date(now),
        rotatedAt: new Date(now),
        expiresAt: new Date(now + 60_000),
        absoluteExpiresAt: new Date(now + 60_000),
        fresh: true,
        actingAs: {
          realIdentityId: 'admin',
          startedAt: new Date(now),
          reason: 'support',
          expiresAt: new Date(now + 3600_000),
        },
      }),
    )
    const fetched = await stores.sessions.getByHash('h1')
    expect(fetched?.aal).toBe(2)
    expect(fetched?.factors[0]!.method).toBe('password')
    expect(fetched?.actingAs?.realIdentityId).toBe('admin')
    expect(fetched?.fresh).toBe(true)
  })

  /**
   * `$type<ProviderLink[]>()` and `$type<Factor[]>()` are assertions drizzle
   * makes to TypeScript, not constraints the database enforces - the column is
   * `NOT NULL json`, which rules out SQL NULL and nothing else. These plant the
   * shapes an older migration, a sibling service, or a hand-run `UPDATE` can
   * leave behind, and pin that a read survives them.
   */
  describe('malformed JSON columns do not take a read down with them', () => {
    async function plantIdentity(providers: unknown): Promise<string> {
      const row = {
        createdAt: new Date(),
        deletedAt: null,
        emailVerified: false,
        id: 'i-malformed',
        profile: { email: 'a@b.com', username: 'a@b.com' },
        providers,
        updatedAt: new Date(),
        version: 1,
      }
      // @ts-expect-error: the point of the test is a row the types forbid
      await bridge.identities.insert(row)
      return row.id
    }

    it.each([
      ['null', null],
      ['an object', {}],
      ['a bare string', 'hello'],
    ])('providers holding %s reads back as no providers rather than throwing', async (_label, value) => {
      const id = await plantIdentity(value)
      const found = await stores.identities.findById(id)
      expect(found?.providers).toEqual([])
    })

    it('drops array entries that are not provider links, which could never match a lookup', async () => {
      const id = await plantIdentity([1, 2, { providerId: 'google', providerSub: 'g1' }])
      const found = await stores.identities.findById(id)
      // The two junk entries used to survive as `{ addedAt: Date }` - objects
      // with no `providerId`, invisible to every link lookup but counted by
      // anything reading `providers.length`.
      expect(found?.providers).toHaveLength(1)
      expect(found?.providers[0]?.providerId).toBe('google')
      expect(found?.providers[0]?.addedAt).toBeInstanceOf(Date)
    })

    it('factors holding a non-array reads back as no factors rather than throwing', async () => {
      const now = new Date()
      const row = {
        aal: 1,
        absoluteExpiresAt: new Date(now.getTime() + 60_000),
        actingAs: null,
        createdAt: now,
        csrfHash: null,
        expiresAt: new Date(now.getTime() + 60_000),
        factors: 'nope',
        fingerprint: null,
        fresh: true,
        id: 'h-malformed',
        identityId: 'i1',
        ip: null,
        kind: 'user',
        rotatedAt: now,
        tenantId: null,
        userAgent: null,
      }
      // @ts-expect-error: the point of the test is a row the types forbid
      await bridge.sessions.insert(row)
      const found = await stores.sessions.getByHash('h-malformed')
      expect(found?.factors).toEqual([])
    })

    it('drops a factor whose method is outside the union, matching the Redis store', async () => {
      const now = new Date()
      const row = {
        aal: 1,
        absoluteExpiresAt: new Date(now.getTime() + 60_000),
        actingAs: null,
        createdAt: now,
        csrfHash: null,
        expiresAt: new Date(now.getTime() + 60_000),
        factors: [
          { completedAt: now, method: 'telepathy' },
          { completedAt: now, method: 'password' },
        ],
        fingerprint: null,
        fresh: true,
        id: 'h-oddfactor',
        identityId: 'i1',
        ip: null,
        kind: 'user',
        rotatedAt: now,
        tenantId: null,
        userAgent: null,
      }
      // @ts-expect-error: the point of the test is a row the types forbid
      await bridge.sessions.insert(row)
      const found = await stores.sessions.getByHash('h-oddfactor')
      // An AAL decision has to read the same on every backend, and a method no
      // `switch` handles is worse than one that is simply absent.
      expect(found?.factors.map((f) => f.method)).toEqual(['password'])
    })
  })

  it('sessions.gc reports deleted count of expired rows', async () => {
    const now = Date.now()
    await stores.sessions.create(
      sessionInput({
        id: 'h1',
        identityId: 'i1',
        kind: 'user',
        aal: 1,
        factors: [],
        createdAt: new Date(now - 10_000),
        rotatedAt: new Date(now - 10_000),
        expiresAt: new Date(now - 5_000),
        absoluteExpiresAt: new Date(now - 5_000),
        fresh: false,
      }),
    )
    await stores.sessions.create(
      sessionInput({
        id: 'h2',
        identityId: 'i1',
        kind: 'user',
        aal: 1,
        factors: [],
        createdAt: new Date(now),
        rotatedAt: new Date(now),
        expiresAt: new Date(now + 60_000),
        absoluteExpiresAt: new Date(now + 60_000),
        fresh: true,
      }),
    )
    const result = await stores.sessions.gc(now)
    expect(result.deleted).toBe(1)
  })
})
