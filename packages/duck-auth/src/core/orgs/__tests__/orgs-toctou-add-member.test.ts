import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { OrgsFacet } from '../orgs.facet'

describe('OrgsFacet.addMember - TOCTOU defense', () => {
  let adapter: MemoryAdapter
  let facet: OrgsFacet

  beforeEach(() => {
    adapter = new MemoryAdapter()
    facet = new OrgsFacet(adapter.orgs, new InMemoryEvents())
    // Seed an org via the underlying adapter (no orgs.create() in facet).
    const orgsMap = (adapter as unknown as { _orgs: Map<string, unknown> })._orgs
    orgsMap.set('org-1', { id: 'org-1', name: 'Acme', createdAt: Date.now() })
  })

  it('two concurrent addMember calls: exactly one resolves, the other rejects with the expected code', async () => {
    const results = await Promise.allSettled([
      facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['admin'] }),
      facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['viewer'] }),
    ])
    const fulfilled = results.filter((r) => r.status === 'fulfilled')
    const rejected = results.filter((r) => r.status === 'rejected')
    expect(fulfilled).toHaveLength(1)
    expect(rejected).toHaveLength(1)
    const firstRejected = rejected[0]
    if (firstRejected && firstRejected.status === 'rejected') {
      expect(firstRejected.reason).toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
        meta: { detail: 'identity already a member of this org' },
      })
    } else {
      throw new Error('expected at least one rejection')
    }
  })

  it('persisted membership reflects the WINNING addMember (not a silent last-write overwrite)', async () => {
    const [a, b] = await Promise.allSettled([
      facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['admin'] }),
      facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['viewer'] }),
    ])
    // Identify the winner by status.
    const winner = a.status === 'fulfilled' ? a.value : b.status === 'fulfilled' ? b.value : null
    expect(winner).not.toBeNull()
    // The persisted state must equal the winner's roles, NOT a silent
    // mix or the loser's overwrite.
    const resolved = await facet.resolveMembership('org-1', 'u')
    expect(resolved).not.toBeNull()
    if (
      winner &&
      typeof winner === 'object' &&
      'roles' in winner &&
      resolved &&
      typeof resolved === 'object' &&
      'roles' in resolved
    ) {
      expect(resolved.roles).toEqual(winner.roles)
    } else {
      throw new Error('expected winner and resolved to both expose roles')
    }
  })

  it('many concurrent addMember calls: exactly one succeeds', async () => {
    const N = 20
    const calls = Array.from({ length: N }, (_, i) =>
      facet.addMember({ orgId: 'org-1', identityId: 'u', roles: [`role-${i}`] }),
    )
    const results = await Promise.allSettled(calls)
    const fulfilled = results.filter((r) => r.status === 'fulfilled')
    const rejected = results.filter((r) => r.status === 'rejected')
    expect(fulfilled).toHaveLength(1)
    expect(rejected).toHaveLength(N - 1)
    // Every rejection must be the duplicate-member error, never a
    // surprise type / DB constraint blow-up.
    for (const r of rejected) {
      if (r.status === 'rejected') {
        expect(r.reason).toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
      }
    }
  })

  it('rejoin after removeMember still works (re-add overwrites leftAt entry)', async () => {
    await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['member'] })
    await facet.removeMember('org-1', 'u')
    const back = await facet.addMember({ orgId: 'org-1', identityId: 'u', roles: ['returned'] })
    expect(back.roles).toEqual(['returned'])
    // leftAt cleared on the new joinedAt row.
    const resolved = await facet.resolveMembership('org-1', 'u')
    expect(resolved?.roles).toEqual(['returned'])
    expect(resolved?.leftAt).toBeNull()
  })

  it('store-level guard fires even when called directly (bypassing the facet)', async () => {
    // Caller that uses the store directly (some apps do this for bulk
    // admin operations). The store must guard atomically too.
    await adapter.orgs.addMember({ orgId: 'org-1', identityId: 'u', roles: [], invitedAt: null, leftAt: null }, {})
    await expect(
      adapter.orgs.addMember({ orgId: 'org-1', identityId: 'u', roles: [], invitedAt: null, leftAt: null }, {}),
    ).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
      meta: { detail: 'identity already a member of this org' },
    })
  })
})
