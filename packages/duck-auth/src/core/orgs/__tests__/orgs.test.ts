import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { OrgsImpl } from '../orgs'

describe('OrgsFacet', () => {
  let adapter: MemoryAdapter
  let events: InMemoryEvents
  let facet: OrgsImpl

  beforeEach(async () => {
    adapter = new MemoryAdapter()
    events = new InMemoryEvents()
    facet = new OrgsImpl(adapter.orgs, events)
    // No orgs.create() in the facet: orgs are the app's own rows, provisioned by its admin flow.
    adapter.seedOrg({ createdAt: new Date(), domain: null, id: 'org-1', metadata: null, name: 'Acme', tenantId: null })
    adapter.seedOrg({
      createdAt: new Date(),
      domain: null,
      id: 'org-2',
      metadata: null,
      name: 'Globex',
      tenantId: null,
    })
  })

  it('every membership and role change reaches the bus', async () => {
    const seen: unknown[] = []
    events.on('org.member.added', (p) => void seen.push(['added', p]))
    events.on('org.roles.set', (p) => void seen.push(['roles', p]))
    events.on('org.member.removed', (p) => void seen.push(['removed', p]))
    await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['viewer'] }, {})
    await facet.setRoles('org-1', 'u', ['admin', 'admin'], {})
    await facet.removeMember('org-1', 'u', {})
    expect(seen).toEqual([
      ['added', expect.objectContaining({ orgId: 'org-1', identityId: 'u', roles: ['viewer'] })],
      ['roles', expect.objectContaining({ orgId: 'org-1', identityId: 'u', roles: ['admin'] })],
      ['removed', expect.objectContaining({ orgId: 'org-1', identityId: 'u' })],
    ])
  })

  describe('addMember', () => {
    it('adds a live membership with starting roles', async () => {
      const m = await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['admin'] }, {})
      expect(m.roles).toEqual(['admin'])
      expect(m.joinedAt).toBeInstanceOf(Date)
    })

    it('rejects adding the same identity twice while membership is live', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['admin'] }, {})
      await expect(facet.addMember({ orgId: 'org-1', identityId: 'u' }, {})).rejects.toMatchObject({
        code: 'AUTH_ALREADY_EXISTS',
      })
    })

    it('allows re-adding after removeMember (rejoin)', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: [] }, {})
      await facet.removeMember('org-1', 'u', {})
      const back = await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['member'] }, {})
      expect(back.roles).toEqual(['member'])
    })
  })

  describe('setRoles + resolveMembership', () => {
    it('replaces the role set + reads via resolveMembership', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['member'] }, {})
      await facet.setRoles('org-1', 'u', ['admin', 'editor'], {})
      const m = await facet.resolveMembership('org-1', 'u', {})
      expect(m.roles).toEqual(['admin', 'editor'])
    })

    it('resolveMembership rejects for non-members', async () => {
      await expect(facet.resolveMembership('org-1', 'ghost', {})).rejects.toMatchObject({
        code: 'AUTH_MEMBERSHIP_NOT_FOUND',
      })
    })

    it('resolveMembership skips left members', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u' }, {})
      await facet.removeMember('org-1', 'u', {})
      await expect(facet.resolveMembership('org-1', 'u', {})).rejects.toMatchObject({
        code: 'AUTH_MEMBERSHIP_NOT_FOUND',
      })
    })
  })

  describe('listForIdentity + listMembers', () => {
    it('listForIdentity returns every org the identity is a live member of', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u' }, {})
      await facet.addMember({ orgId: 'org-2', identityId: 'u' }, {})
      const orgs = await facet.listForIdentity('u', {})
      expect(orgs.map((o) => o.id).sort()).toEqual(['org-1', 'org-2'])
    })

    it('listMembers returns every live member of an org', async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u1' }, {})
      await facet.addMember({ orgId: 'org-1', identityId: 'u2' }, {})
      await facet.addMember({ orgId: 'org-1', identityId: 'u3' }, {})
      await facet.removeMember('org-1', 'u2', {})
      const ms = await facet.listMembers('org-1', {})
      expect(ms.map((m) => m.identityId).sort()).toEqual(['u1', 'u3'])
    })
  })
  describe('the facet answers with the row or rejects', () => {
    it('rejects absence, and orNull reads it back as null', async () => {
      await expect(facet.get('nope', {})).rejects.toMatchObject({ code: 'AUTH_ORG_NOT_FOUND' })
      await expect(facet.get('nope', {}).orNull()).resolves.toBeNull()
      await expect(facet.resolveMembership('org-1', 'nobody', {})).rejects.toMatchObject({
        code: 'AUTH_MEMBERSHIP_NOT_FOUND',
      })
      await expect(facet.resolveMembership('org-1', 'nobody', {}).orNull()).resolves.toBeNull()
    })

    it('answers the seeded org rather than a nullable one', async () => {
      await expect(facet.get('org-1', {})).resolves.toMatchObject({ id: 'org-1', name: 'Acme' })
    })
  })
})
