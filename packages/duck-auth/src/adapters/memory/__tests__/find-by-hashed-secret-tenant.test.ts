import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '..'

describe('MemoryAdapter.findByHashedSecret - tenant filter parity with SQL adapter', () => {
  it('returns null when ctx.tenantId mismatches the row tenantId', async () => {
    const adapter = new MemoryAdapter<{ email: string }>()
    const ident = await adapter.identities.create(
      { profile: { email: 'svc@x.com' }, providers: [] },
      { tenantId: 'tenant-A' },
    )
    await adapter.credentials.upsert(
      { identityId: ident.id, kind: 'api-key', secret: 'hash-secret-1', tenantId: 'tenant-A' },
      { tenantId: 'tenant-A' },
    )
    const fromTenantB = await adapter.credentials.findByHashedSecret('hash-secret-1', 'api-key', {
      tenantId: 'tenant-B',
    })
    expect(fromTenantB).toBeNull()
  })

  it('returns the row when ctx.tenantId matches', async () => {
    const adapter = new MemoryAdapter<{ email: string }>()
    const ident = await adapter.identities.create(
      { profile: { email: 'svc@x.com' }, providers: [] },
      { tenantId: 'tenant-A' },
    )
    await adapter.credentials.upsert(
      { identityId: ident.id, kind: 'api-key', secret: 'hash-secret-2', tenantId: 'tenant-A' },
      { tenantId: 'tenant-A' },
    )
    const fromTenantA = await adapter.credentials.findByHashedSecret('hash-secret-2', 'api-key', {
      tenantId: 'tenant-A',
    })
    expect(fromTenantA?.identityId).toBe(ident.id)
  })

  it('returns global (no tenantId) rows from any tenant scope (SQL adapter parity)', async () => {
    const adapter = new MemoryAdapter<{ email: string }>()
    const ident = await adapter.identities.create({ profile: { email: 'global@x.com' }, providers: [] }, {})
    await adapter.credentials.upsert({ identityId: ident.id, kind: 'api-key', secret: 'hash-secret-3' }, {})
    const fromTenantA = await adapter.credentials.findByHashedSecret('hash-secret-3', 'api-key', {
      tenantId: 'tenant-A',
    })
    expect(fromTenantA?.identityId).toBe(ident.id)
  })

  it('returns tenant-scoped row when ctx tenantId is undefined (global search)', async () => {
    const adapter = new MemoryAdapter<{ email: string }>()
    const ident = await adapter.identities.create(
      { profile: { email: 'svc@x.com' }, providers: [] },
      { tenantId: 'tenant-A' },
    )
    await adapter.credentials.upsert(
      { identityId: ident.id, kind: 'api-key', secret: 'hash-secret-4', tenantId: 'tenant-A' },
      { tenantId: 'tenant-A' },
    )
    const found = await adapter.credentials.findByHashedSecret('hash-secret-4', 'api-key', {})
    expect(found?.identityId).toBe(ident.id)
  })

  it('upsert inherits ctx.tenantId when input.tenantId is unset (SQL adapter parity)', async () => {
    const adapter = new MemoryAdapter<{ email: string }>()
    const ident = await adapter.identities.create(
      { profile: { email: 'i@x.com' }, providers: [] },
      { tenantId: 'tenant-A' },
    )
    // No tenantId in input; ctx supplies it.
    await adapter.credentials.upsert(
      { identityId: ident.id, kind: 'api-key', secret: 'hash-secret-6' },
      { tenantId: 'tenant-A' },
    )
    const fromTenantA = await adapter.credentials.findByHashedSecret('hash-secret-6', 'api-key', {
      tenantId: 'tenant-A',
    })
    expect(fromTenantA?.tenantId).toBe('tenant-A')
    const fromTenantB = await adapter.credentials.findByHashedSecret('hash-secret-6', 'api-key', {
      tenantId: 'tenant-B',
    })
    expect(fromTenantB).toBeNull()
  })

  it('treats revokedAt:0 as revoked (defense against legacy falsy bug)', async () => {
    const adapter = new MemoryAdapter<{ email: string }>()
    const ident = await adapter.identities.create({ profile: { email: 'r@x.com' }, providers: [] }, {})
    await adapter.credentials.upsert({ identityId: ident.id, kind: 'api-key', secret: 'hash-secret-5' }, {})
    const all = await adapter.credentials.listByIdentity(ident.id, 'api-key', {})
    const row = all[0]!
    ;(row as { revokedAt?: number }).revokedAt = 0
    const found = await adapter.credentials.findByHashedSecret('hash-secret-5', 'api-key', {})
    expect(found?.revokedAt).toBe(0)
  })
})
