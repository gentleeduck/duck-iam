import { beforeEach, describe, expect, it } from 'vitest'
import { AuthMemoryAdapter } from '../../../adapters/memory'
import { AuthInMemoryEvents } from '../../events'
import { OrgsFacet } from '../orgs'

describe('OrgsFacet roles sanitization', () => {
  let adapter: AuthMemoryAdapter
  let facet: OrgsFacet

  beforeEach(() => {
    adapter = new AuthMemoryAdapter()
    facet = new OrgsFacet(adapter.orgs, new AuthInMemoryEvents())
    const orgsMap = (adapter as unknown as { _orgs: Map<string, unknown> })._orgs
    orgsMap.set('org-1', { id: 'org-1', name: 'Acme', createdAt: Date.now() })
  })

  describe('addMember', () => {
    it('passes through a well-formed roles array', async () => {
      const m = await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['admin', 'editor'] })
      expect(m.roles).toEqual(['admin', 'editor'])
    })

    it('drops non-string entries', async () => {
      const roles = ['admin', 42, null, undefined, true, { x: 1 }, [], 'editor'] as unknown as string[]
      const m = await facet.addMember({ orgId: 'org-1', identityId: 'u', roles })
      expect(m.roles).toEqual(['admin', 'editor'])
    })

    it('drops empty-string entries', async () => {
      const m = await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['admin', '', 'editor'] })
      expect(m.roles).toEqual(['admin', 'editor'])
    })

    it('drops oversize entries (>128 chars)', async () => {
      const big = 'A'.repeat(129)
      const m = await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['admin', big, 'editor'] })
      expect(m.roles).toEqual(['admin', 'editor'])
    })

    it('caps the array at 64 entries', async () => {
      const huge = Array.from({ length: 1000 }, (_, i) => `role-${i}`)
      const m = await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: huge })
      expect(m.roles).toHaveLength(64)
      expect(m.roles[0]).toBe('role-0')
      expect(m.roles[63]).toBe('role-63')
    })

    it('handles `roles: undefined` (no roles supplied)', async () => {
      const m = await facet.addMember({ orgId: 'org-1', identityId: 'u' })
      expect(m.roles).toEqual([])
    })

    it('handles `roles: non-array` (silently -> [])', async () => {
      const m = await facet.addMember({
        orgId: 'org-1',
        identityId: 'u',
        roles: 'admin' as unknown as string[],
      })
      expect(m.roles).toEqual([])
    })
  })

  describe('setRoles', () => {
    beforeEach(async () => {
      await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['initial'] })
    })

    it('passes through a well-formed replacement', async () => {
      await facet.setRoles('org-1', 'u', ['new-admin', 'new-editor'])
      const m = await facet.resolveMembership('org-1', 'u')
      expect(m?.roles).toEqual(['new-admin', 'new-editor'])
    })

    it('drops mixed-type entries on replacement', async () => {
      const roles = ['admin', null, 42, 'editor'] as unknown as string[]
      await facet.setRoles('org-1', 'u', roles)
      const m = await facet.resolveMembership('org-1', 'u')
      expect(m?.roles).toEqual(['admin', 'editor'])
    })

    it('caps replacement at 64 entries', async () => {
      const huge = Array.from({ length: 100 }, (_, i) => `r${i}`)
      await facet.setRoles('org-1', 'u', huge)
      const m = await facet.resolveMembership('org-1', 'u')
      expect(m?.roles).toHaveLength(64)
    })

    it('drops oversize per-role strings on replacement', async () => {
      const big = 'B'.repeat(500)
      await facet.setRoles('org-1', 'u', ['ok', big, 'also-ok'])
      const m = await facet.resolveMembership('org-1', 'u')
      expect(m?.roles).toEqual(['ok', 'also-ok'])
    })
  })
})
