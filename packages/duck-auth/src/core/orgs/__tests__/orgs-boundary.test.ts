/**
 * Org membership is an authorization boundary: `resolveMembership` is what an
 * application asks before deciding whether someone may act inside an
 * organisation, and the roles it returns are what the answer is built from.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { OrgsImpl } from '../orgs'
import type { Org } from '../orgs.types'

const ORG = 'org-1'
const OTHER_ORG = 'org-2'

function makeOrgs() {
  const adapter = new MemoryAdapter()
  return new OrgsImpl(adapter.orgs, new InMemoryEvents())
}

describe('membership answers only for the org that was asked about', () => {
  it('resolves a live member', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['member'] }, {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual(['member'])
  })

  it('does not answer for a different org', async () => {
    // The cross-org read: membership of one organisation must never satisfy a
    // check made about another.
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] }, {})
    await expect(orgs.resolveMembership(OTHER_ORG, 'u1', {})).rejects.toMatchObject({
      code: 'AUTH_MEMBERSHIP_NOT_FOUND',
    })
  })

  it('does not answer for a different identity', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] }, {})
    await expect(orgs.resolveMembership(ORG, 'u2', {})).rejects.toMatchObject({ code: 'AUTH_MEMBERSHIP_NOT_FOUND' })
  })

  it('rejects for an org nobody has joined', async () => {
    await expect(makeOrgs().resolveMembership('never-created', 'u1', {})).rejects.toMatchObject({
      code: 'AUTH_MEMBERSHIP_NOT_FOUND',
    })
  })

  it('keeps two orgs’ role sets apart for the same person', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] }, {})
    await orgs.addMember({ identityId: 'u1', orgId: OTHER_ORG, roles: ['viewer'] }, {})

    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual(['owner'])
    expect((await orgs.resolveMembership(OTHER_ORG, 'u1', {})).roles).toEqual(['viewer'])
  })

  it('lists only the members of the org asked about', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [] }, {})
    await orgs.addMember({ identityId: 'u2', orgId: ORG, roles: [] }, {})
    await orgs.addMember({ identityId: 'u3', orgId: OTHER_ORG, roles: [] }, {})

    expect((await orgs.listMembers(ORG, {})).map((m) => m.identityId).sort()).toEqual(['u1', 'u2'])
  })

  it('lists no one who left, from a host store that answers every row, as resolveMembership refuses them', async () => {
    const row = (identityId: string, leftAt: Date | null): Org.Membership => ({
      identityId,
      invitedAt: null,
      joinedAt: new Date(),
      leftAt,
      orgId: ORG,
      roles: ['owner'],
      tenantId: null,
    })
    const everyRow: Org.Store = {
      ...new MemoryAdapter().orgs,
      listMembers: async () => [row('u1', null), row('u2', new Date())],
    }
    const orgs = new OrgsImpl(everyRow, new InMemoryEvents())

    expect((await orgs.listMembers(ORG, {})).map((m) => m.identityId)).toEqual(['u1'])
    await expect(orgs.resolveMembership(ORG, 'u2', {})).rejects.toMatchObject({ code: 'AUTH_MEMBERSHIP_NOT_FOUND' })
  })
})

describe('granting roles cannot create a membership', () => {
  it('setRoles on someone who never joined leaves them a non-member', async () => {
    // If this upserted, "grant a role" would double as "add to the org", and any
    // caller able to set roles could add themselves.
    const orgs = makeOrgs()
    // Through `orNull`, because the claim is what it did to the membership, not that it refused.
    await orgs.setRoles(ORG, 'never-a-member', ['owner'], {}).orNull()
    await expect(orgs.resolveMembership(ORG, 'never-a-member', {})).rejects.toMatchObject({
      code: 'AUTH_MEMBERSHIP_NOT_FOUND',
    })
  })

  it('setRoles on a removed member does not bring them back', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['member'] }, {})
    await orgs.removeMember(ORG, 'u1', {})

    await orgs.setRoles(ORG, 'u1', ['owner'], {}).orNull()
    await expect(orgs.resolveMembership(ORG, 'u1', {})).rejects.toMatchObject({ code: 'AUTH_MEMBERSHIP_NOT_FOUND' })
  })

  it('setRoles on a member of another org does not reach across', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: OTHER_ORG, roles: ['viewer'] }, {})

    await orgs.setRoles(ORG, 'u1', ['owner'], {}).orNull()
    await expect(orgs.resolveMembership(ORG, 'u1', {})).rejects.toMatchObject({ code: 'AUTH_MEMBERSHIP_NOT_FOUND' })
    expect((await orgs.resolveMembership(OTHER_ORG, 'u1', {})).roles).toEqual(['viewer'])
  })

  it('setRoles replaces the set rather than adding to it', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner', 'billing'] }, {})
    await orgs.setRoles(ORG, 'u1', ['viewer'], {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual(['viewer'])
  })

  it('setRoles can strip every role without removing the membership', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] }, {})
    await orgs.setRoles(ORG, 'u1', [], {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual([])
  })
})

describe('leaving and rejoining', () => {
  it('a removed member stops resolving', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] }, {})
    await orgs.removeMember(ORG, 'u1', {})
    await expect(orgs.resolveMembership(ORG, 'u1', {})).rejects.toMatchObject({ code: 'AUTH_MEMBERSHIP_NOT_FOUND' })
  })

  it('removing twice is harmless, and both calls say what they left', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [] }, {})

    const first = await orgs.removeMember(ORG, 'u1', {})
    const second = await orgs.removeMember(ORG, 'u1', {})

    // The row is still there once left, so the second call answers with it too
    // - idempotent, and honest about which membership it names.
    expect(first.leftAt).toBeInstanceOf(Date)
    expect(second.identityId).toBe('u1')
  })

  it('removing someone who was never a member rejects, and orNull reads that as nothing to remove', async () => {
    // Not a silent success. The rejection is what an idempotent caller opts out of with `orNull`,
    // rather than every caller having to tell "removed nothing" from "removed a row" by eye.
    await expect(makeOrgs().removeMember(ORG, 'stranger', {})).rejects.toMatchObject({
      code: 'AUTH_MEMBERSHIP_NOT_FOUND',
    })
    await expect(makeOrgs().removeMember(ORG, 'stranger', {}).orNull()).resolves.toBeNull()
  })

  it('setRoles answers with the roles it actually stored, not the ones passed in', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [] }, {})

    // The list is sanitized on the way in; the answer is the stored set, so a
    // caller sees what was dropped without re-reading the membership.
    const updated = await orgs.setRoles(ORG, 'u1', ['owner', '', 'member'], {})

    expect(updated.roles).toEqual(['owner', 'member'])
    await expect(orgs.setRoles(ORG, 'stranger', ['owner'], {}).orNull()).resolves.toBeNull()
  })

  it('rejoining is allowed once the previous membership ended', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] }, {})
    await orgs.removeMember(ORG, 'u1', {})
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['member'] }, {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual(['member'])
  })

  it('rejoining does not inherit the roles held before leaving', async () => {
    // Otherwise removing an owner and re-adding them as a viewer would silently
    // hand back ownership.
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner', 'billing'] }, {})
    await orgs.removeMember(ORG, 'u1', {})
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['viewer'] }, {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual(['viewer'])
  })

  it('refuses to add someone who is already a live member', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['member'] }, {})
    await expect(orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] }, {})).rejects.toMatchObject({
      code: 'AUTH_ALREADY_EXISTS',
    })
  })

  it('a refused duplicate add leaves the original roles untouched', async () => {
    // The escalation this blocks: re-adding yourself with a better role set.
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['viewer'] }, {})
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['owner'] }, {}).catch(() => undefined)
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual(['viewer'])
  })
})

describe('the role list is bounded, and what that does not include', () => {
  it('drops non-string entries', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: JSON.parse('["ok", 42, null, {}, []]') }, {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual(['ok'])
  })

  it('drops empty and oversize entries', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['', 'x'.repeat(129), 'kept'] }, {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual(['kept'])
  })

  it('keeps an entry exactly at the length limit', async () => {
    const orgs = makeOrgs()
    const role = 'x'.repeat(128)
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [role] }, {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual([role])
  })

  it('caps the list at sixty-four entries', async () => {
    const orgs = makeOrgs()
    await orgs.addMember(
      {
        identityId: 'u1',
        orgId: ORG,
        roles: Array.from({ length: 200 }, (_, i) => `role-${i}`),
      },
      {},
    )
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toHaveLength(64)
  })

  it('treats a non-array roles value as no roles', async () => {
    const orgs = makeOrgs()
    // @ts-expect-error a string, not a list
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: 'owner' }, {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual([])
  })

  it('deduplicates before counting the cap, so padding cannot push out a real grant', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['admin', 'admin', 'admin'] }, {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual(['admin'])

    // Sixty-four copies of one role used to fill the budget on their own and drop everything
    // behind them, which is a padded list silently deleting a grant.
    const padded = [...Array.from({ length: 64 }, () => 'viewer'), 'owner']
    await orgs.addMember({ identityId: 'u2', orgId: ORG, roles: padded }, {})
    expect((await orgs.resolveMembership(ORG, 'u2', {})).roles).toEqual(['viewer', 'owner'])
  })

  it('keeps first-seen order and still stops at sixty-four distinct roles', async () => {
    const orgs = makeOrgs()
    const many = Array.from({ length: 70 }, (_, i) => `r${i}`)
    await orgs.addMember({ identityId: 'u3', orgId: ORG, roles: many }, {})
    const { roles } = await orgs.resolveMembership(ORG, 'u3', {})
    expect(roles).toHaveLength(64)
    expect(roles[0]).toBe('r0')
    expect(roles.at(-1)).toBe('r63')
  })

  it('keeps roles as opaque strings, without folding case or trimming', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['Owner', ' owner ', 'owner'] }, {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual(['Owner', ' owner ', 'owner'])
  })

  it('treats a role differing only by case as a different role', async () => {
    // Worth pinning: an application checking `roles.includes('owner')` will not
    // match a stored `Owner`.
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['Owner'] }, {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).not.toContain('owner')
  })

  it('stores an injection payload as an ordinary role string', async () => {
    const orgs = makeOrgs()
    const role = `'; DROP TABLE auth_orgs; --`
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [role] }, {})
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual([role])
  })
})

describe('listing an identity’s orgs', () => {
  it('returns nothing for someone with no memberships', async () => {
    expect(await makeOrgs().listForIdentity('stranger', {})).toEqual([])
  })

  it('does not list an org the identity has left', async () => {
    const orgs = makeOrgs()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [] }, {})
    await orgs.removeMember(ORG, 'u1', {})
    expect(await orgs.listForIdentity('u1', {})).toEqual([])
  })
})

describe('events name only memberships that are live', () => {
  function withEvents(store: Org.Store = new MemoryAdapter().orgs) {
    const events = new InMemoryEvents()
    const seen: string[] = []
    events.on('org.member.added', (p) => void seen.push(`added ${p.identityId} ${p.roles.join(',')}`))
    events.on('org.roles.set', (p) => void seen.push(`roles ${p.identityId} ${p.roles.join(',')}`))
    events.on('org.member.removed', (p) => void seen.push(`removed ${p.identityId}`))
    return { orgs: new OrgsImpl(store, events), seen }
  }

  it('refuses roles for a member who left, and emits no org.roles.set that would grant them again', async () => {
    const { orgs, seen } = withEvents()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['admin'] }, {})
    await orgs.removeMember(ORG, 'u1', {})

    await expect(orgs.setRoles(ORG, 'u1', ['owner'], {})).rejects.toMatchObject({ code: 'AUTH_MEMBERSHIP_NOT_FOUND' })
    expect(seen).toEqual(['added u1 admin', 'removed u1'])

    await orgs.addMember({ identityId: 'u2', orgId: ORG, roles: [] }, {})
    await orgs.setRoles(ORG, 'u2', ['owner'], {})
    expect(seen.at(-1)).toBe('roles u2 owner')
  })

  it('refuses roles a host store wrote onto a membership that had ended', async () => {
    const adapter = new MemoryAdapter()
    const left: Org.Membership = {
      identityId: 'u1',
      invitedAt: null,
      joinedAt: new Date(),
      leftAt: new Date(),
      orgId: ORG,
      roles: ['owner'],
      tenantId: null,
    }
    const { orgs, seen } = withEvents({ ...adapter.orgs, setRoles: async () => left })

    await expect(orgs.setRoles(ORG, 'u1', ['owner'], {})).rejects.toMatchObject({ code: 'AUTH_MEMBERSHIP_NOT_FOUND' })
    expect(seen).toEqual([])
  })

  it('emits org.member.removed once, for the call that ended the membership', async () => {
    const { orgs, seen } = withEvents()
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [] }, {})
    await orgs.removeMember(ORG, 'u1', {})
    expect((await orgs.removeMember(ORG, 'u1', {})).leftAt).toBeInstanceOf(Date)
    expect(seen.filter((e) => e === 'removed u1')).toHaveLength(1)

    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: [] }, {})
    await orgs.removeMember(ORG, 'u1', {})
    expect(seen.filter((e) => e === 'removed u1')).toHaveLength(2)
  })
})

describe('an id from an unchecked request body', () => {
  const body: { orgId: string; identityId: string } = JSON.parse('{"orgId":"org-1","identityId":null}')
  const empty = { identityId: '', orgId: ORG }

  it('refuses a null or empty orgId or identityId on every write', async () => {
    const orgs = makeOrgs()
    for (const ids of [body, empty, { identityId: 'u1', orgId: '' }]) {
      await expect(orgs.addMember({ ...ids, roles: ['admin'] }, {})).rejects.toMatchObject({
        code: 'AUTH_INVALID_PARAMETERS',
      })
      await expect(orgs.removeMember(ids.orgId, ids.identityId, {})).rejects.toMatchObject({
        code: 'AUTH_INVALID_PARAMETERS',
      })
      await expect(orgs.setRoles(ids.orgId, ids.identityId, ['admin'], {})).rejects.toMatchObject({
        code: 'AUTH_INVALID_PARAMETERS',
      })
    }
    expect(await orgs.listMembers(ORG, {})).toEqual([])
  })

  it('answers no membership for a null identity, as a guest session carries, even where a store holds one', async () => {
    const adapter = new MemoryAdapter()
    const orgs = new OrgsImpl(adapter.orgs, new InMemoryEvents())
    await orgs.addMember({ identityId: 'u1', orgId: ORG, roles: ['viewer'] }, {})
    const planted: Org.Membership = {
      ...body,
      invitedAt: null,
      joinedAt: new Date(),
      leftAt: null,
      roles: ['admin'],
      tenantId: null,
    }
    adapter.raw.memberships.set('planted', planted)
    adapter.seedOrg({ createdAt: new Date(), domain: null, id: ORG, metadata: null, name: ORG, tenantId: null })

    await expect(orgs.resolveMembership(ORG, body.identityId, {})).rejects.toMatchObject({
      code: 'AUTH_MEMBERSHIP_NOT_FOUND',
    })
    expect(await orgs.listForIdentity(body.identityId, {})).toEqual([])
    expect((await orgs.resolveMembership(ORG, 'u1', {})).roles).toEqual(['viewer'])
    expect(await orgs.listForIdentity('u1', {})).toHaveLength(1)
  })
})
