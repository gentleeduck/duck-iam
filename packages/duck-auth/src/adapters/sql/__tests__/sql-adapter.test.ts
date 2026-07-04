import { beforeEach, describe, expect, it } from 'vitest'
import type { Credential, Identity } from '../../../core/types/identity'
import type { Session } from '../../../core/types/session'
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
  const identities = new Map<string, Identity.Me<ProfileShape>>()
  const credentials = new Map<string, Credential.Me>()
  const sessions = new Map<string, Session.Me>()

  return {
    identities: {
      findById: async (id, tid) => {
        const r = identities.get(id)
        return r && (tid === undefined || r.tenantId === tid || r.tenantId === null) ? r : null
      },
      findByEmail: async (email, tid) => {
        for (const r of identities.values()) {
          if (tid !== undefined && r.tenantId !== tid && r.tenantId !== null) continue
          const profile = r.profile as { email?: string } | null
          if (profile?.email === email) return r
        }
        return null
      },
      findByProviderSub: async (providerId, sub, tid) => {
        for (const r of identities.values()) {
          if (tid !== undefined && r.tenantId !== tid && r.tenantId !== null) continue
          if (r.providers.some((l) => l.providerId === providerId && l.providerSub === sub)) return r
        }
        return null
      },
      insert: async (row) => {
        identities.set(row.id, row)
      },
      updateConditional: async (id, patch, expectedVersion, _tid) => {
        const cur = identities.get(id)
        if (!cur || cur.version !== expectedVersion) return null
        const next = { ...cur, ...patch } as Identity.Me<ProfileShape>
        identities.set(id, next)
        return next
      },
      softDelete: async (id, deletedAt) => {
        const cur = identities.get(id)
        if (cur) identities.set(id, { ...cur, deletedAt })
      },
      restore: async (id) => {
        const cur = identities.get(id)
        if (!cur) return null
        const next = { ...cur, deletedAt: null }
        identities.set(id, next)
        return next
      },
      erase: async (id) => {
        identities.delete(id)
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt) => {
        const cur = identities.get(identityId)
        if (!cur) return
        identities.set(identityId, { ...cur, providers: [...cur.providers, { providerId, providerSub, addedAt }] })
      },
      deleteProviderLink: async (identityId, providerId) => {
        const cur = identities.get(identityId)
        if (!cur) return
        identities.set(identityId, {
          ...cur,
          providers: cur.providers.filter((l) => l.providerId !== providerId),
        })
      },
      merge: async (survivorId, dupId) => {
        for (const c of credentials.values()) {
          if (c.identityId === dupId) c.identityId = survivorId
        }
        for (const s of sessions.values()) {
          if (s.identityId === dupId) s.identityId = survivorId
        }
        identities.delete(dupId)
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
        if (cur) credentials.set(id, { ...cur, revokedAt: new Date(revokedAt) })
      },
      delete: async (id) => {
        credentials.delete(id)
      },
      deleteByKind: async (identityId, kind) => {
        for (const [id, r] of credentials) {
          if (r.identityId === identityId && r.kind === kind) credentials.delete(id)
        }
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
        const next = { ...cur, ...patch } as Session.Me
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
      { profile: { username: 'a@b.com', email: 'a@b.com', name: 'A' }, providers: [] },
      {},
    )
    expect(ident.id).toBeTruthy()
    const fetched = await stores.identities.findById(ident.id, {})
    expect(fetched?.profile?.email).toBe('a@b.com')
    expect(fetched?.profile?.name).toBe('A')
  })

  it('identities.findByEmail decodes the JSON profile', async () => {
    await stores.identities.create({ profile: { username: 'x@y.com', email: 'x@y.com' }, providers: [] }, {})
    const found = await stores.identities.findByEmail('x@y.com', {})
    expect(found?.profile?.email).toBe('x@y.com')
  })

  it('identities.update bumps version + rejects stale writes', async () => {
    const ident = await stores.identities.create(
      { profile: { username: 'a@b.com', email: 'a@b.com' }, providers: [] },
      {},
    )
    const v2 = await stores.identities.update(ident.id, { profile: { username: 'b@b.com', email: 'b@b.com' } }, 1, {})
    expect(v2.version).toBe(2)
    expect(v2.profile?.email).toBe('b@b.com')
    await expect(
      stores.identities.update(ident.id, { profile: { username: 'c@b.com', email: 'c@b.com' } }, 1, {}),
    ).rejects.toMatchObject({
      code: 'AUTH_STALE_WRITE',
    })
  })

  it('credentials.upsert + findByHashedSecret round-trips secret + metadata', async () => {
    const ident = await stores.identities.create(
      { profile: { username: 'a@b.com', email: 'a@b.com' }, providers: [] },
      {},
    )
    await stores.credentials.upsert(
      { identityId: ident.id, kind: 'password', secret: 'hash:xyz', metadata: { strength: 0.9 } },
      {},
    )
    const found = await stores.credentials.findByHashedSecret('hash:xyz', 'password', {})
    expect(found?.identityId).toBe(ident.id)
    expect((found?.metadata as { strength: number }).strength).toBe(0.9)
  })

  it('credentials.rotate bumps version', async () => {
    const ident = await stores.identities.create(
      { profile: { username: 'a@b.com', email: 'a@b.com' }, providers: [] },
      {},
    )
    const cred = await stores.credentials.upsert({ identityId: ident.id, kind: 'password', secret: 's1' }, {})
    const rotated = await stores.credentials.rotate(cred.id, 's2', cred.version, {})
    expect(rotated.secret).toBe('s2')
    expect(rotated.version).toBe(cred.version + 1)
  })

  it('sessions.create -> getByHash round-trips factors + actingAs JSON', async () => {
    const now = Date.now()
    await stores.sessions.create({
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
    })
    const fetched = await stores.sessions.getByHash('h1')
    expect(fetched?.aal).toBe(2)
    expect(fetched?.factors[0]!.method).toBe('password')
    expect(fetched?.actingAs?.realIdentityId).toBe('admin')
    expect(fetched?.fresh).toBe(true)
  })

  it('sessions.gc reports deleted count of expired rows', async () => {
    const now = Date.now()
    await stores.sessions.create({
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
    })
    await stores.sessions.create({
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
    })
    const result = await stores.sessions.gc(now)
    expect(result.deleted).toBe(1)
  })
})
