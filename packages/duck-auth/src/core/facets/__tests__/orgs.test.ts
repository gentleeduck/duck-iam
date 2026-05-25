import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAuthAdapter } from '../../../adapters/memory'
import { InMemoryEvents } from '../../events'
import { OrgsFacet } from '../orgs'

describe('OrgsFacet', () => {
  let adapter: MemoryAuthAdapter
  let events: InMemoryEvents
  let facet: OrgsFacet

  beforeEach(async () => {
    adapter = new MemoryAuthAdapter()
    events = new InMemoryEvents()
    facet = new OrgsFacet(adapter.orgs, events)
    // Seed two orgs via the underlying adapter (no orgs.create() in the facet
    // since orgs are typically pre-provisioned via the app's own admin flow).
    ;(adapter as unknown as { _orgs: Map<string, unknown> })._orgs.set('org-1', {
      id: 'org-1',
      name: 'Acme',
      createdAt: Date.now(),
    })
    ;(adapter as unknown as { _orgs: Map<string, unknown> })._orgs.set('org-2', {
      id: 'org-2',
      name: 'Globex',
      createdAt: Date.now(),
    })
  })

  describe('addMember', () => {
    it('adds a live membership with starting roles', async () => {
      const m = await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['admin'] })
      expect(m.roles).toEqual(['admin'])
      expect(m.joinedAt).toBeGreaterThan(0)
    })

    it('rejects adding the same identity twice while membership is live', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['admin'] })
      await expect(facet.addMember({ orgId: 'org-1', identityId: 'u' })).rejects.toMatchObject({
        code: 'AUTH/PROVIDER_FAILED',
      })
    })

    it('allows re-adding after removeMember (rejoin)', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: [] })
      await facet.removeMember('org-1', 'u')
      const back = await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['member'] })
      expect(back.roles).toEqual(['member'])
    })
  })

  describe('setRoles + resolveMembership', () => {
    it('replaces the role set + reads via resolveMembership', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['member'] })
      await facet.setRoles('org-1', 'u', ['admin', 'editor'])
      const m = await facet.resolveMembership('org-1', 'u')
      expect(m?.roles).toEqual(['admin', 'editor'])
    })

    it('resolveMembership returns null for non-members', async () => {
      const m = await facet.resolveMembership('org-1', 'ghost')
      expect(m).toBeNull()
    })

    it('resolveMembership skips left members', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u' })
      await facet.removeMember('org-1', 'u')
      const m = await facet.resolveMembership('org-1', 'u')
      expect(m).toBeNull()
    })
  })

  describe('listForIdentity + listMembers', () => {
    it('listForIdentity returns every org the identity is a live member of', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u' })
      await facet.addMember({ orgId: 'org-2', identityId: 'u' })
      const orgs = await facet.listForIdentity('u')
      expect(orgs.map((o) => o.id).sort()).toEqual(['org-1', 'org-2'])
    })

    it('listMembers returns every live member of an org', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u1' })
      await facet.addMember({ orgId: 'org-1', identityId: 'u2' })
      await facet.addMember({ orgId: 'org-1', identityId: 'u3' })
      await facet.removeMember('org-1', 'u2')
      const ms = await facet.listMembers('org-1')
      expect(ms.map((m) => m.identityId).sort()).toEqual(['u1', 'u3'])
    })
  })
})
