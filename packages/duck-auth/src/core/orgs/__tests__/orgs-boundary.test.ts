/**
 * Org membership is an authorization boundary: `resolveMembership` is what an
 * application asks before deciding whether someone may act inside an
 * organisation, and the roles it returns are what the answer is built from.
 *
 * The existing tests cover role sanitisation and the add-member race. These cover
 * the boundary itself, which is where privilege escalation would live: granting
 * roles to someone who is not a member, a removed member still resolving, one
 * org's membership answering for another, and the ways a role list can be padded.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { OrgsImpl } from '../orgs'

const ORG = 'org-1'
const OTHER_ORG = 'org-2'

function makeOrgs() {
  const adapter = new MemoryAdapter()
  return new OrgsImpl(adapter.orgs, new InMemoryEvents())
}

describe('membership answers only for the org that was asked about', () => {
  it('resolves a live member', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['member'] })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual(['member'])
  })

  it('does not answer for a different org', async () => {
    // The cross-org read: membership of one organisation must never satisfy a
    // check made about another.
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] })
    expect(await orgs.resolveMembership(OTHER_ORG, 'u1')).toBeNull()
  })

  it('does not answer for a different identity', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] })
    expect(await orgs.resolveMembership(ORG, 'u2')).toBeNull()
  })

  it('returns null for an org nobody has joined', async () => {
    expect(await makeOrgs().resolveMembership('never-created', 'u1')).toBeNull()
  })

  it('keeps two orgs’ role sets apart for the same person', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] })
    await orgs.addMember({ identityId: 'u1', orgId: OTHER_ORG, roles: ['viewer'] })

    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual(['owner'])
    expect((await orgs.resolveMembership(OTHER_ORG, 'u1'))?.roles).toEqual(['viewer'])
  })

  it('lists only the members of the org asked about', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [] })
    await orgs.addMember({ identityId: 'u2', orgId: ORG, roles: [] })
    await orgs.addMember({ identityId: 'u3', orgId: OTHER_ORG, roles: [] })

    expect((await orgs.listMembers(ORG)).map((m) => m.identityId).sort()).toEqual(['u1', 'u2'])
  })
})

describe('granting roles cannot create a membership', () => {
  it('setRoles on someone who never joined leaves them a non-member', async () => {
    // If this upserted, "grant a role" would double as "add to the org", and any
    // caller able to set roles could add themselves.
    const orgs = makeOrgs()
    await orgs.setRoles(ORG, 'never-a-member', ['owner'])
    expect(await orgs.resolveMembership(ORG, 'never-a-member')).toBeNull()
  })

  it('setRoles on a removed member does not bring them back', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['member'] })
    await orgs.removeMember(ORG, 'u1')

    await orgs.setRoles(ORG, 'u1', ['owner'])
    expect(await orgs.resolveMembership(ORG, 'u1')).toBeNull()
  })

  it('setRoles on a member of another org does not reach across', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: OTHER_ORG, roles: ['viewer'] })

    await orgs.setRoles(ORG, 'u1', ['owner'])
    expect(await orgs.resolveMembership(ORG, 'u1')).toBeNull()
    expect((await orgs.resolveMembership(OTHER_ORG, 'u1'))?.roles).toEqual(['viewer'])
  })

  it('setRoles replaces the set rather than adding to it', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner', 'billing'] })
    await orgs.setRoles(ORG, 'u1', ['viewer'])
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual(['viewer'])
  })

  it('setRoles can strip every role without removing the membership', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] })
    await orgs.setRoles(ORG, 'u1', [])
    const membership = await orgs.resolveMembership(ORG, 'u1')
    expect(membership).not.toBeNull()
    expect(membership?.roles).toEqual([])
  })
})

describe('leaving and rejoining', () => {
  it('a removed member stops resolving', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] })
    await orgs.removeMember(ORG, 'u1')
    expect(await orgs.resolveMembership(ORG, 'u1')).toBeNull()
  })

  it('removing twice is harmless', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [] })
    await orgs.removeMember(ORG, 'u1')
    await expect(orgs.removeMember(ORG, 'u1')).resolves.toBeUndefined()
  })

  it('removing someone who was never a member is harmless', async () => {
    await expect(makeOrgs().removeMember(ORG, 'stranger')).resolves.toBeUndefined()
  })

  it('rejoining is allowed once the previous membership ended', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] })
    await orgs.removeMember(ORG, 'u1')
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['member'] })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual(['member'])
  })

  it('rejoining does not inherit the roles held before leaving', async () => {
    // Otherwise removing an owner and re-adding them as a viewer would silently
    // hand back ownership.
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner', 'billing'] })
    await orgs.removeMember(ORG, 'u1')
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['viewer'] })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual(['viewer'])
  })

  it('refuses to add someone who is already a live member', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['member'] })
    await expect(orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] })).rejects.toMatchObject({
      code: 'AUTH_PROVIDER_FAILED',
    })
  })

  it('a refused duplicate add leaves the original roles untouched', async () => {
    // The escalation this blocks: re-adding yourself with a better role set.
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['viewer'] })
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] }).catch(() => undefined)
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual(['viewer'])
  })
})

describe('the role list is bounded, and what that does not include', () => {
  it('drops non-string entries', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['ok', 42, null, {}, []] as never })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual(['ok'])
  })

  it('drops empty and oversize entries', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['', 'x'.repeat(129), 'kept'] })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual(['kept'])
  })

  it('keeps an entry exactly at the length limit', async () => {
    const orgs = makeOrgs()
    const role = 'x'.repeat(128)
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [role] })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual([role])
  })

  it('caps the list at sixty-four entries', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({
      identityId: 'u1',
      orgId: ORG,
      roles: Array.from({ length: 200 }, (_, i) => `role-${i}`),
    })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toHaveLength(64)
  })

  it('treats a non-array roles value as no roles', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: 'owner' as never })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual([])
  })

  it('FINDING: duplicates are kept, and count against the sixty-four cap', async () => {
    // `sanitizeRoles` filters by type and length but does not deduplicate, so a
    // caller can pad a list with one role repeated. Harmless for an `includes`
    // check, but sixty-four copies of `viewer` fill the budget and silently push
    // out the roles that follow, so a padded list can drop a real grant.
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['admin', 'admin', 'admin'] })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual(['admin', 'admin', 'admin'])

    const padded = [...Array.from({ length: 64 }, () => 'viewer'), 'owner']
    await orgs.addMember({ identityId: 'u2', orgId: ORG, roles: padded })
    const roles = (await orgs.resolveMembership(ORG, 'u2'))?.roles ?? []
    expect(roles).toHaveLength(64)
    expect(roles).not.toContain('owner')
  })

  it('keeps roles as opaque strings, without folding case or trimming', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['Owner', ' owner ', 'owner'] })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual(['Owner', ' owner ', 'owner'])
  })

  it('treats a role differing only by case as a different role', async () => {
    // Worth pinning: an application checking `roles.includes('owner')` will not
    // match a stored `Owner`.
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['Owner'] })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).not.toContain('owner')
  })

  it('stores an injection payload as an ordinary role string', async () => {
    const orgs = makeOrgs()
    const role = `'; DROP TABLE auth_orgs; --`
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [role] })
    expect((await orgs.resolveMembership(ORG, 'u1'))?.roles).toEqual([role])
  })
})

describe('listing an identity’s orgs', () => {
  it('returns nothing for someone with no memberships', async () => {
    expect(await makeOrgs().listForIdentity('stranger')).toEqual([])
  })

  it('does not list an org the identity has left', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [] })
    await orgs.removeMember(ORG, 'u1')
    expect(await orgs.listForIdentity('u1')).toEqual([])
  })
})
