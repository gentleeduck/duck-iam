import { describe, expect, it } from 'vitest'
import { ALL_TENANTS } from '~/core/tenant'
import { MemoryAdapter } from '../index'

const member = { identityId: 'u1', invitedAt: null, leftAt: null, orgId: 'org-1', roles: [], tenantId: 'tenant-a' }

describe('the memory orgs store writes a membership only in the tenant the call names', () => {
  it('refuses a tenant row to a call naming no tenant', async () => {
    const a = new MemoryAdapter()

    await expect(a.orgs.addMember(member, {})).rejects.toMatchObject({
      code: 'AUTH_TENANT_SCOPE_VIOLATION',
      meta: { asked: null, got: 'tenant-a' },
    })
  })

  it('writes it for its own tenant, or for ALL_TENANTS', async () => {
    const a = new MemoryAdapter()

    await expect(a.orgs.addMember(member, { tenantId: 'tenant-a' })).resolves.toMatchObject({ tenantId: 'tenant-a' })
    await expect(a.orgs.addMember({ ...member, identityId: 'u2' }, ALL_TENANTS)).resolves.toMatchObject({
      tenantId: 'tenant-a',
    })
  })
})
