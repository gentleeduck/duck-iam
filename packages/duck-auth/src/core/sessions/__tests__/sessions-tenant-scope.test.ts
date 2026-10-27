/** D4 - sessions were the only tenant-scoped store with no tenant parameter. */

import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { sha256 } from '~/core/crypto'
import { FakeRedis } from '~/core/drivers/redis-like'
import { AuthEngine } from '~/core/engine'
import type { Identities } from '~/core/identities/identities.types'
import { RedisSessionImpl } from '~/core/sessions/sessions.redis'
import { ALL_TENANTS } from '~/core/tenant'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'

interface MyProfile extends Identities.ProfileMetadataBase {}

function build() {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://app',
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid' }),
  })
  const revoked: string[] = []
  auth.events.on('session.revoked', (p) => {
    revoked.push(p.sessionId)
  })
  return { adapter, auth, revoked }
}

describe('D4 - sessions are tenant-scopable', () => {
  let auth: AuthEngine<MyProfile>
  let revoked: string[]
  let id: string
  let sidA: string
  let sidB: string
  let sidGlobal: string

  beforeEach(async () => {
    ;({ auth, revoked } = build())
    // One person, three sessions: tenant A, tenant B, and one with no tenant.
    // This is the shape the finding turns on - identities are global, so all
    // three are the same `identityId`.
    const ident = await auth.identities.create({ profile: { email: 'sam@x.com', username: 'sam@x.com' } })
    id = ident.id
    sidA = (await auth.sessions.create({ aal: 1, factors: [], identityId: id, kind: 'user', tenantId: 'a' })).sid
    sidB = (await auth.sessions.create({ aal: 1, factors: [], identityId: id, kind: 'user', tenantId: 'b' })).sid
    sidGlobal = (await auth.sessions.create({ aal: 1, factors: [], identityId: id, kind: 'user' })).sid
  })

  it('listForIdentity naming no tenant answers the session with none, and ALL_TENANTS every one', async () => {
    expect((await auth.sessions.listForIdentity(id)).map((s) => s.tenantId)).toEqual([null])
    expect(await auth.sessions.listForIdentity(id, ALL_TENANTS)).toHaveLength(3)
  })

  it("listForIdentity scoped does not show tenant A the other tenant's devices", async () => {
    const a = await auth.sessions.listForIdentity(id, { tenantId: 'a' })
    expect(a).toHaveLength(1)
    expect(a[0]?.tenantId).toBe('a')
    // Not merely a count: the leak was IP, user-agent and session existence.
    expect(a.map((s) => s.id)).not.toContain((await auth.sessions.getBySid(sidB)).id)
  })

  it('a session with no tenant belongs to no tenant, rather than to all of them', async () => {
    const a = await auth.sessions.listForIdentity(id, { tenantId: 'a' })
    expect(a.map((s) => s.tenantId)).toEqual(['a'])
    // And a read naming no tenant finds it.
    expect((await auth.sessions.listForIdentity(id)).some((s) => s.tenantId === null)).toBe(true)
  })

  it('revokeAllForIdentity scoped leaves the person signed in to the other tenant', async () => {
    const gone = await auth.sessions.revokeAllForIdentity(id, { tenantId: 'a' })
    expect(gone).toHaveLength(1)
    await expect(auth.sessions.getBySid(sidA)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    expect((await auth.sessions.getBySid(sidB)).tenantId).toBe('b')
    await expect(auth.sessions.getBySid(sidGlobal)).resolves.toBeDefined()
  })

  it('a scoped revoke emits one session.revoked, not three', async () => {
    await auth.sessions.revokeAllForIdentity(id, { tenantId: 'a' })
    expect(revoked).toHaveLength(1)
  })

  it('revokeAllForIdentity naming no tenant ends the session with none, and ALL_TENANTS every one', async () => {
    const gone = await auth.sessions.revokeAllForIdentity(id)
    expect(gone.map((s) => s.tenantId)).toEqual([null])
    expect(await auth.sessions.listForIdentity(id, ALL_TENANTS)).toHaveLength(2)
    await auth.sessions.revokeAllForIdentity(id, ALL_TENANTS)
    expect(await auth.sessions.listForIdentity(id, ALL_TENANTS)).toEqual([])
    expect(revoked).toHaveLength(3)
  })

  it('a credential change ends the sessions of every tenant, and reports each', async () => {
    // Not held to the session's tenant: a changed credential ends every session the account holds.
    const ids = await Promise.all([sidA, sidB, sidGlobal].map(async (sid) => (await auth.sessions.getBySid(sid)).id))
    await auth.sessions.rotateOrCreate({
      aal: 1,
      factors: [],
      identityId: id,
      kind: 'user',
      previousSid: sidA,
      purpose: 'credential-change',
    })
    await expect(auth.sessions.getBySid(sidB)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    await expect(auth.sessions.getBySid(sidGlobal)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    expect([...revoked].sort()).toEqual([...ids].sort())
  })
})

describe('D4 - the Redis store keeps its index reachable after a scoped sweep', () => {
  it('sessions the scoped delete spared are still listable and still revocable', async () => {
    // The index is keyed by identity alone, so the `ALL_TENANTS` path `del`s the whole
    // key. A scoped delete that did the same would strand tenant B's rows: alive,
    // absent from every `listByIdentity`, and unreachable by any later sweep -
    // a session nothing can sign out.
    const store = new RedisSessionImpl({ prefix: 't', redis: new FakeRedis() })
    const now = new Date()
    const exp = new Date(now.getTime() + 60_000)
    const base = {
      absoluteExpiresAt: exp,
      aal: 1 as const,
      actingAs: null,
      createdAt: now,
      updatedAt: now,
      csrfHash: null,
      expiresAt: exp,
      factors: [],
      fingerprint: null,
      fresh: true,
      identityId: 'sam',
      ip: null,
      kind: 'user' as const,
      rotatedAt: now,
      userAgent: null,
    }
    await store.create({ ...base, id: sha256('ra'), tenantId: 'a' })
    await store.create({ ...base, id: sha256('rb'), tenantId: 'b' })

    await store.deleteAllForIdentity('sam', { tenantId: 'a' })

    expect((await store.listByIdentity('sam', ALL_TENANTS)).map((s) => s.id)).toEqual([sha256('rb')])
    await store.deleteAllForIdentity('sam', ALL_TENANTS)
    expect(await store.listByIdentity('sam', ALL_TENANTS)).toEqual([])
    await expect(store.getByHash(sha256('rb'))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })
})
