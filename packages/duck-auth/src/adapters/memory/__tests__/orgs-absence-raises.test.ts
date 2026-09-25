import { describe, expect, it } from 'vitest'
import { orNull } from '~/core/answer'
import { MemoryAdapter } from '../index'

/** A store answers a miss by raising, never with a null, so a caller cannot read "not there" as "not asked".
 *  `orNull` is the one way absence becomes a value, and it only converts the codes that mean absence. */
describe('the orgs store raises on a miss', () => {
  it('getOrg raises for an org that was never seeded', async () => {
    const a = new MemoryAdapter()
    await expect(a.orgs.getOrg('nope', {})).rejects.toMatchObject({ code: 'AUTH_ORG_NOT_FOUND' })
    await expect(orNull(a.orgs.getOrg('nope', {}))).resolves.toBeNull()
  })

  it('removeMember and setRoles raise for someone who never joined', async () => {
    const a = new MemoryAdapter()
    await a.orgs.addMember(
      { identityId: 'u1', invitedAt: null, leftAt: null, orgId: 'org-1', roles: [], tenantId: null },
      {},
    )

    for (const call of [
      () => a.orgs.removeMember('org-1', 'stranger', {}),
      () => a.orgs.setRoles('org-1', 'stranger', ['owner'], {}),
    ]) {
      await expect(call()).rejects.toMatchObject({ code: 'AUTH_MEMBERSHIP_NOT_FOUND' })
      await expect(orNull(call())).resolves.toBeNull()
    }
  })
})
