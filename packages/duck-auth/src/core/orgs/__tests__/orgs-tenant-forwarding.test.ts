/**
 * Every `OrgsImpl` method defaults its `TenantContext` to `{}`, which makes dropping the argument on
 * the way to the store type-safe and invisible - the shape that locked accounts out of their tenant
 * in `completePasswordReset`. `Org.Store` is a read interface over the host's own tables, so the
 * host owns the scoping; what the library owes them is that the context they pass arrives unchanged.
 *
 * NOTE: the shipped memory store ignores the context on all six methods, and neither `Org.Me` nor
 * `Org.Membership` carries a tenant field, so nothing here can be asserted against it. The recording
 * store below stands in for a host's tenant-aware one.
 */

import { describe, expect, it } from 'vitest'
import { InMemoryEvents } from '~/core/events'
import type { TenantContext } from '~/core/tenant/tenant.types'
import { OrgsImpl } from '../orgs'
import type { Org } from '../orgs.types'

const TENANT: TenantContext = { tenantId: 'tenant-a' }

function membership(overrides: Partial<Org.Membership> = {}): Org.Membership {
  return {
    identityId: 'u1',
    invitedAt: null,
    joinedAt: new Date(),
    leftAt: null,
    orgId: 'org-1',
    roles: [],
    ...overrides,
  }
}

/** Records the context each method was handed, so a dropped argument is visible. */
function recordingStore(): { store: Org.Store; seen: Map<string, TenantContext | undefined> } {
  const seen = new Map<string, TenantContext | undefined>()
  const store: Org.Store = {
    addMember: async (m, ctx) => {
      seen.set('addMember', ctx)
      return membership({ ...m, joinedAt: new Date() })
    },
    getOrg: async (id, ctx) => {
      seen.set('getOrg', ctx)
      return { createdAt: new Date(), domain: null, id, metadata: null, name: id }
    },
    listMembers: async (orgId, ctx) => {
      // `addMember` reads this first; answer empty there so its conflict check passes.
      if (!seen.has('listMembers')) seen.set('listMembers', ctx)
      return orgId === 'org-empty' ? [] : [membership()]
    },
    listOrgsForIdentity: async (_identityId, ctx) => {
      seen.set('listOrgsForIdentity', ctx)
      return []
    },
    removeMember: async (orgId, identityId, ctx) => {
      seen.set('removeMember', ctx)
      return membership({ identityId, leftAt: new Date(), orgId })
    },
    setRoles: async (orgId, identityId, roles, ctx) => {
      seen.set('setRoles', ctx)
      return membership({ identityId, orgId, roles })
    },
  }
  return { seen, store }
}

describe('OrgsImpl forwards the tenant context it was given', () => {
  it('every method hands the store the caller context, not its own default', async () => {
    const { seen, store } = recordingStore()
    const facet = new OrgsImpl(store, new InMemoryEvents())

    await facet.get('org-1', TENANT)
    await facet.listForIdentity('u1', TENANT)
    await facet.listMembers('org-1', TENANT)
    await facet.addMember({ identityId: 'u2', orgId: 'org-empty', roles: ['admin'] }, TENANT)
    await facet.removeMember('org-1', 'u1', TENANT)
    await facet.setRoles('org-1', 'u1', ['admin'], TENANT)

    const methods = ['getOrg', 'listOrgsForIdentity', 'listMembers', 'addMember', 'removeMember', 'setRoles']
    expect([...seen.keys()].sort()).toEqual([...methods].sort())
    for (const m of methods) {
      expect(seen.get(m), `${m} dropped the tenant context`).toEqual(TENANT)
    }
  })

  it("addMember's own conflict read is scoped too, or it answers from another tenant", async () => {
    const { seen, store } = recordingStore()
    const facet = new OrgsImpl(store, new InMemoryEvents())

    await facet.addMember({ identityId: 'u2', orgId: 'org-empty', roles: [] }, TENANT)

    expect(seen.get('listMembers')).toEqual(TENANT)
  })

  it('resolveMembership scopes the read it decides on', async () => {
    const { seen, store } = recordingStore()
    const facet = new OrgsImpl(store, new InMemoryEvents())

    await facet.resolveMembership('org-1', 'u1', TENANT)

    expect(seen.get('listMembers')).toEqual(TENANT)
  })

  it('an omitted context reaches the store as the empty one, which is not a tenant', async () => {
    const { seen, store } = recordingStore()
    const facet = new OrgsImpl(store, new InMemoryEvents())

    await facet.listMembers('org-1')

    // Pinned deliberately: `{}` is what a store sees when the caller names no tenant, and a store
    // that reads it as "every tenant" is reading it correctly. The default is the library's, so a
    // host implementing `Org.Store` can rely on the distinction.
    expect(seen.get('listMembers')).toEqual({})
  })
})
