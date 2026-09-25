/**
 * `Org.Store` is a read interface over the host's own tables, so the host still performs the scoping.
 * What changed is that the library no longer has to take that on trust: every method requires the
 * context rather than defaulting it to `{}` - the shape that locked accounts out of their tenant in
 * `completePasswordReset` - and every row answers with the tenant it was read under, so the facet
 * refuses one from anywhere else. This file covers the forwarding half: that the context the caller
 * named is the one the store is handed.
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
    tenantId: TENANT.tenantId ?? null,
    ...overrides,
  }
}

/** Records the context each method was handed, so a dropped argument is visible. Every row answers
 *  under the tenant it was asked for, which is what a correctly scoped host store does. */
function recordingStore(): { store: Org.Store; seen: Map<string, TenantContext | undefined> } {
  const seen = new Map<string, TenantContext | undefined>()
  const store: Org.Store = {
    addMember: async (m, ctx) => {
      seen.set('addMember', ctx)
      return membership({ ...m, joinedAt: new Date(), tenantId: ctx.tenantId ?? null })
    },
    getOrg: async (id, ctx) => {
      seen.set('getOrg', ctx)
      return { createdAt: new Date(), domain: null, id, metadata: null, name: id, tenantId: ctx.tenantId ?? null }
    },
    listMembers: async (orgId, ctx) => {
      // `addMember` reads this first; answer empty there so its conflict check passes.
      if (!seen.has('listMembers')) seen.set('listMembers', ctx)
      return orgId === 'org-empty' ? [] : [membership({ tenantId: ctx.tenantId ?? null })]
    },
    listOrgsForIdentity: async (_identityId, ctx) => {
      seen.set('listOrgsForIdentity', ctx)
      return []
    },
    removeMember: async (orgId, identityId, ctx) => {
      seen.set('removeMember', ctx)
      return membership({ identityId, leftAt: new Date(), orgId, tenantId: ctx.tenantId ?? null })
    },
    setRoles: async (orgId, identityId, roles, ctx) => {
      seen.set('setRoles', ctx)
      return membership({ identityId, orgId, roles, tenantId: ctx.tenantId ?? null })
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

  it('the empty context reaches the store as itself, and is not a tenant', async () => {
    const { seen, store } = recordingStore()
    const facet = new OrgsImpl(store, new InMemoryEvents())

    await facet.listMembers('org-1', {})

    // Pinned deliberately: `{}` is what a store sees when the caller names no tenant, and a store
    // that reads it as "every tenant" is reading it correctly. It now has to be written out, so a
    // host implementing `Org.Store` sees a caller that meant it rather than one that forgot.
    expect(seen.get('listMembers')).toEqual({})
  })
})
