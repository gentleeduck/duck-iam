/**
 * `exportAll` is the GDPR right-to-access blob and was the one caller in the package that read the session
 * store without the tenant context it had been handed - one line below the credentials read that passes it.
 * `sessions-tenant-scope.test.ts` (D4) already proves the store and `SessionsImpl.listForIdentity` honour
 * the filter, which is the point: a scope only applies where a caller asks for it.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { sha256 } from '~/core/crypto'
import { FakeRedis } from '~/core/drivers/redis-like'
import { InMemoryEvents } from '~/core/events'
import type { Identities } from '~/core/identities/identities.types'
import { RedisSessionImpl } from '~/core/sessions/sessions.redis'
import type { Sessions } from '~/core/sessions/sessions.types'
import { credentialInput, sessionInput } from '~/test/store-inputs'
import { IdentitiesImpl } from '../identities'
import { DEFAULT_IDENTITIES_CONFIG } from '../identities.constants'

interface MyProfile extends Identities.ProfileMetadataBase {}

const A = 'tenant-a'
const B = 'tenant-b'

/** Every field the store contract names as what an unfiltered read hands the wrong tenant. */
function session(tag: string, tenantId: string | null, identityId: string): Sessions.CreateInput {
  const now = Date.now()
  return sessionInput({
    aal: 1,
    absoluteExpiresAt: new Date(now + 60_000),
    createdAt: new Date(now),
    csrfHash: `csrf-${tag}`,
    expiresAt: new Date(now + 60_000),
    factors: [{ completedAt: new Date(now), method: 'password' }],
    fingerprint: `fp-${tag}`,
    fresh: true,
    id: sha256(`sid-${tag}`),
    identityId,
    ip: `10.0.0.${tag}`,
    kind: 'user',
    rotatedAt: new Date(now),
    tenantId,
    userAgent: `ua-${tag}`,
  })
}

/** The caller is what is under test, so the fix has to hold over both shipped session stores. */
const STORES: Array<[string, (a: MemoryAdapter<MyProfile>) => Sessions.Store]> = [
  ['memory', (a) => a.sessions],
  ['redis', () => new RedisSessionImpl({ prefix: 'test:export', redis: new FakeRedis() })],
]

describe.each(STORES)('exportAll narrows to the asking tenant (%s sessions)', (_label, makeSessions) => {
  let adapter: MemoryAdapter<MyProfile>
  let sessions: Sessions.Store
  let facet: IdentitiesImpl<MyProfile>
  let id: string

  beforeEach(async () => {
    adapter = new MemoryAdapter<MyProfile>()
    sessions = makeSessions(adapter)
    facet = new IdentitiesImpl<MyProfile>(adapter.identities, new InMemoryEvents(), DEFAULT_IDENTITIES_CONFIG)
    id = (await facet.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })).id
    // One person, signed in to two tenants and holding one session that belongs to neither.
    await sessions.create(session('1', A, id))
    await sessions.create(session('2', B, id))
    await sessions.create(session('3', null, id))
    await adapter.credentials.create(
      credentialInput({ identityId: id, kind: 'password', secret: 'hash-a', tenantId: A }),
      {},
    )
    await adapter.credentials.create(
      credentialInput({ identityId: id, kind: 'api-key', secret: 'hash-b', tenantId: B }),
      {},
    )
  })

  const exported = (ctx: { tenantId?: string }) => facet.exportAll(id, adapter.credentials, ctx, { sessions })

  it('unscoped answers every session, so a single-tenant export is unchanged', async () => {
    // Live control: `inTenant` treats an absent `tenantId` as matching everything, which is why passing
    // the context through is not a behaviour change for the deployments that never set one.
    const blob = await exported({})
    expect(blob.sessions.map((s) => s.id).sort()).toEqual([sha256('sid-1'), sha256('sid-2'), sha256('sid-3')].sort())
  })

  it("does not hand one tenant the other tenant's sessions", async () => {
    const blob = await exported({ tenantId: A })
    expect(blob.sessions.map((s) => s.id)).toEqual([sha256('sid-1')])
  })

  it('names none of the other tenant, its address, its device or its agent anywhere in the blob', async () => {
    const json = IdentitiesImpl.exportToJson(await exported({ tenantId: A }))
    expect(json).not.toContain(B)
    expect(json).not.toContain('10.0.0.2')
    expect(json).not.toContain('ua-2')
    expect(json).not.toContain('fp-2')
  })

  it('a session belonging to no tenant is not the asking tenant’s either', async () => {
    // The store contract is exact about this: a named `tenantId` matches exactly, so a global row is
    // nobody's to export.
    const blob = await exported({ tenantId: A })
    expect(blob.sessions.map((s) => s.id)).not.toContain(sha256('sid-3'))
  })

  it("still carries the asking tenant's own session in full", async () => {
    const blob = await exported({ tenantId: A })
    expect(blob.sessions[0]).toMatchObject({ fingerprint: 'fp-1', ip: '10.0.0.1', tenantId: A, userAgent: 'ua-1' })
  })

  it('answers an empty list for a tenant this person never signed in to, without emptying the blob', async () => {
    const blob = await exported({ tenantId: 'tenant-c' })
    expect(blob.sessions).toEqual([])
    expect(blob.identity.id).toBe(id)
  })

  it('scopes the credentials list the same way, which that read already did', async () => {
    // Live control: the sibling line was right all along, and is what makes the session line read as a
    // deliberate omission rather than a layer nobody had scoped yet.
    const blob = await exported({ tenantId: A })
    expect(blob.credentials.map((c) => c.kind)).toEqual(['password'])
  })

  it('still strips the csrf hash from every session it does carry', async () => {
    // Live control: the redaction below the fix is untouched by it.
    const blob = await exported({ tenantId: A })
    expect(blob.sessions[0]).not.toHaveProperty('csrfHash')
    expect(IdentitiesImpl.exportToJson(blob)).not.toContain('csrf-1')
  })

  it('answers an empty list when no session store is supplied at all', async () => {
    // Live control: the scoping is on the read, not on whether there is one.
    const blob = await facet.exportAll(id, adapter.credentials, { tenantId: A })
    expect(blob.sessions).toEqual([])
  })
})
