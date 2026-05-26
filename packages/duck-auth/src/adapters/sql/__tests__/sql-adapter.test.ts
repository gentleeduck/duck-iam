/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it } from 'vitest'
import {
  createSqlAuthStores,
  type SqlBridge,
  type SqlCredentialRow,
  type SqlIdentityRow,
  type SqlSessionRow,
} from '../index'

/**
 * Pure in-memory `SqlBridge` for tests. Mirrors the rowwise contract a
 * real ORM impl would expose. Sufficient to exercise the wrapper logic
 * (JSON encode/decode, tenant scoping, optimistic version, null vs
 * undefined coercion) without spinning up Postgres.
 */
function makeInMemoryBridge(): SqlBridge {
  const identities = new Map<string, SqlIdentityRow>()
  const credentials = new Map<string, SqlCredentialRow>()
  const sessions = new Map<string, SqlSessionRow>()

  return {
    identities: {
      findById: async (id, tid) => {
        const r = identities.get(id)
        return r && (tid === undefined || r.tenantId === tid || r.tenantId === null) ? r : null
      },
      findByEmail: async (email, tid) => {
        for (const r of identities.values()) {
          if (tid !== undefined && r.tenantId !== tid && r.tenantId !== null) continue
          const profile = r.profile ? (JSON.parse(r.profile) as { email?: string }) : undefined
          if (profile?.email === email) return r
        }
        return null
      },
      findByProviderSub: async (providerId, sub, tid) => {
        for (const r of identities.values()) {
          if (tid !== undefined && r.tenantId !== tid && r.tenantId !== null) continue
          const links = JSON.parse(r.providers) as Array<{ providerId: string; providerSub?: string }>
          if (links.some((l) => l.providerId === providerId && l.providerSub === sub)) return r
        }
        return null
      },
      insert: async (row) => {
        identities.set(row.id, row)
      },
      updateConditional: async (id, patch, expectedVersion, _tid) => {
        const cur = identities.get(id)
        if (!cur || cur.version !== expectedVersion) return null
        const next = { ...cur, ...patch } as SqlIdentityRow
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
        const links = JSON.parse(cur.providers) as Array<{
          providerId: string
          providerSub?: string
          addedAt: number
        }>
        links.push({ providerId, providerSub, addedAt })
        identities.set(identityId, { ...cur, providers: JSON.stringify(links) })
      },
      deleteProviderLink: async (identityId, providerId) => {
        const cur = identities.get(identityId)
        if (!cur) return
        const links = (JSON.parse(cur.providers) as Array<{ providerId: string }>).filter(
          (l) => l.providerId !== providerId,
        )
        identities.set(identityId, { ...cur, providers: JSON.stringify(links) })
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
          const meta = r.metadata ? (JSON.parse(r.metadata) as { provider?: string; sub?: string }) : null
          if (meta?.provider === provider && meta.sub === sub) return r
        }
        return null
      },
      findByHashedSecret: async (secretHash, kind) => {
        for (const r of credentials.values()) {
          if (r.kind === kind && r.secret === secretHash) return r
        }
        return null
      },
      insert: async (row) => {
        credentials.set(row.id, row)
      },
      updateConditional: async (id, patch, expectedVersion) => {
        const cur = credentials.get(id)
        if (!cur || cur.version !== expectedVersion) return null
        const next = { ...cur, ...patch } as SqlCredentialRow
        credentials.set(id, next)
        return next
      },
      revoke: async (id, revokedAt) => {
        const cur = credentials.get(id)
        if (cur) credentials.set(id, { ...cur, revokedAt })
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
        const next = { ...cur, ...patch } as SqlSessionRow
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
          if (s.absoluteExpiresAt < now) {
            sessions.delete(id)
            deleted++
          }
        }
        return deleted
      },
    },
  }
}

describe('createSqlAuthStores', () => {
  interface ProfileShape {
    email: string
    name?: string
  }
  let bridge: SqlBridge
  let stores: ReturnType<typeof createSqlAuthStores<ProfileShape>>

  beforeEach(() => {
    bridge = makeInMemoryBridge()
    stores = createSqlAuthStores<ProfileShape>(bridge)
  })

  it('identities.create -> findById round-trips the profile JSON encoded', async () => {
    const ident = await stores.identities.create({ profile: { email: 'a@b.com', name: 'A' }, providers: [] }, {})
    expect(ident.id).toBeTruthy()
    const fetched = await stores.identities.findById(ident.id, {})
    expect(fetched?.profile?.email).toBe('a@b.com')
    expect(fetched?.profile?.name).toBe('A')
  })

  it('identities.findByEmail decodes the JSON profile', async () => {
    await stores.identities.create({ profile: { email: 'x@y.com' }, providers: [] }, {})
    const found = await stores.identities.findByEmail('x@y.com', {})
    expect(found?.profile?.email).toBe('x@y.com')
  })

  it('identities.update bumps version + rejects stale writes', async () => {
    const ident = await stores.identities.create({ profile: { email: 'a@b.com' }, providers: [] }, {})
    const v2 = await stores.identities.update(ident.id, { profile: { email: 'b@b.com' } }, 1, {})
    expect(v2.version).toBe(2)
    expect(v2.profile?.email).toBe('b@b.com')
    await expect(stores.identities.update(ident.id, { profile: { email: 'c@b.com' } }, 1, {})).rejects.toMatchObject({
      code: 'AUTH/STALE_WRITE',
    })
  })

  it('credentials.upsert + findByHashedSecret round-trips secret + metadata', async () => {
    const ident = await stores.identities.create({ profile: { email: 'a@b.com' }, providers: [] }, {})
    await stores.credentials.upsert(
      { identityId: ident.id, kind: 'password', secret: 'hash:xyz', metadata: { strength: 0.9 } },
      {},
    )
    const found = await stores.credentials.findByHashedSecret('hash:xyz', 'password', {})
    expect(found?.identityId).toBe(ident.id)
    expect((found?.metadata as { strength: number }).strength).toBe(0.9)
  })

  it('credentials.rotate bumps version', async () => {
    const ident = await stores.identities.create({ profile: { email: 'a@b.com' }, providers: [] }, {})
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
      factors: [{ method: 'password', completedAt: now }],
      createdAt: now,
      rotatedAt: now,
      expiresAt: now + 60_000,
      absoluteExpiresAt: now + 60_000,
      fresh: true,
      actingAs: { realIdentityId: 'admin', startedAt: now, reason: 'support', expiresAt: now + 3600_000 },
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
      createdAt: now - 10_000,
      rotatedAt: now - 10_000,
      expiresAt: now - 5_000,
      absoluteExpiresAt: now - 5_000,
      fresh: false,
    })
    await stores.sessions.create({
      id: 'h2',
      identityId: 'i1',
      kind: 'user',
      aal: 1,
      factors: [],
      createdAt: now,
      rotatedAt: now,
      expiresAt: now + 60_000,
      absoluteExpiresAt: now + 60_000,
      fresh: true,
    })
    const result = await stores.sessions.gc(now)
    expect(result.deleted).toBe(1)
  })
})
