import { describe, expect, it } from 'vitest'
import { credentialInput, identityInput } from '~/test/store-inputs'
import { MemoryAdapter } from '..'

describe('MemoryAdapter.findByHashedSecret - tenant filter parity with SQL adapter', () => {
  it('raises when ctx.tenantId mismatches the row tenantId', async () => {
    const adapter = new MemoryAdapter<{ email: string; username: string }>()
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'svc@x.com', username: 'svc@x.com' }, providers: [] }),
    )
    await adapter.credentials.create(
      credentialInput({ identityId: ident.id, kind: 'api-key', secret: 'hash-secret-1', tenantId: 'tenant-A' }),
      { tenantId: 'tenant-A' },
    )
    await expect(
      adapter.credentials.findByHashedSecret('hash-secret-1', 'api-key', { tenantId: 'tenant-B' }),
    ).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
  })

  it('returns the row when ctx.tenantId matches', async () => {
    const adapter = new MemoryAdapter<{ email: string; username: string }>()
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'svc@x.com', username: 'svc@x.com' }, providers: [] }),
    )
    await adapter.credentials.create(
      credentialInput({ identityId: ident.id, kind: 'api-key', secret: 'hash-secret-2', tenantId: 'tenant-A' }),
      { tenantId: 'tenant-A' },
    )
    const fromTenantA = await adapter.credentials.findByHashedSecret('hash-secret-2', 'api-key', {
      tenantId: 'tenant-A',
    })
    expect(fromTenantA?.identityId).toBe(ident.id)
  })

  it('does NOT return a global (no tenantId) row to a tenant-scoped caller', async () => {
    const adapter = new MemoryAdapter<{ email: string; username: string }>()
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'global@x.com', username: 'global@x.com' }, providers: [] }),
    )
    await adapter.credentials.create(
      credentialInput({ identityId: ident.id, kind: 'api-key', secret: 'hash-secret-3' }),
      {},
    )
    // This case used to assert the opposite, in the name of "SQL adapter
    // parity" - but every dialect scopes with a bare `eq(tenant_id, $1)` and SQL
    // NULL equals nothing, so no real backend has ever returned this row here.
    // Verified against sqlite: findById, findByHashedSecret and listByIdentity
    // all miss it. A credential belonging to no tenant must not authenticate one.
    await expect(
      adapter.credentials.findByHashedSecret('hash-secret-3', 'api-key', { tenantId: 'tenant-A' }),
    ).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })

    // Still reachable by an unscoped caller, which is what makes it global.
    await expect(adapter.credentials.findByHashedSecret('hash-secret-3', 'api-key', {})).resolves.toBeTruthy()
  })

  it('returns tenant-scoped row when ctx tenantId is undefined (global search)', async () => {
    const adapter = new MemoryAdapter<{ email: string; username: string }>()
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'svc@x.com', username: 'svc@x.com' }, providers: [] }),
    )
    await adapter.credentials.create(
      credentialInput({ identityId: ident.id, kind: 'api-key', secret: 'hash-secret-4', tenantId: 'tenant-A' }),
      { tenantId: 'tenant-A' },
    )
    const found = await adapter.credentials.findByHashedSecret('hash-secret-4', 'api-key', {})
    expect(found?.identityId).toBe(ident.id)
  })

  it('create inherits ctx.tenantId when input.tenantId is unset (SQL adapter parity)', async () => {
    const adapter = new MemoryAdapter<{ email: string; username: string }>()
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'i@x.com', username: 'i@x.com' }, providers: [] }),
    )
    // No tenantId in input; ctx supplies it.
    await adapter.credentials.create(
      credentialInput({ identityId: ident.id, kind: 'api-key', secret: 'hash-secret-6' }),
      { tenantId: 'tenant-A' },
    )
    const fromTenantA = await adapter.credentials.findByHashedSecret('hash-secret-6', 'api-key', {
      tenantId: 'tenant-A',
    })
    expect(fromTenantA?.tenantId).toBe('tenant-A')
    await expect(
      adapter.credentials.findByHashedSecret('hash-secret-6', 'api-key', { tenantId: 'tenant-B' }),
    ).rejects.toMatchObject({ code: 'AUTH_CREDENTIAL_NOT_FOUND' })
  })

  it('treats revokedAt:0 as revoked (defense against legacy falsy bug)', async () => {
    const adapter = new MemoryAdapter<{ email: string; username: string }>()
    const ident = await adapter.identities.create(
      identityInput({ profile: { email: 'r@x.com', username: 'r@x.com' }, providers: [] }),
    )
    await adapter.credentials.create(
      credentialInput({ identityId: ident.id, kind: 'api-key', secret: 'hash-secret-5' }),
      {},
    )
    const all = await adapter.credentials.listByIdentity(ident.id, 'api-key', {})
    const row = all[0]!
    // @ts-expect-error: SEC test intentionally violates the typed shape
    adapter.raw.credentials.set(row.id, { ...row, revokedAt: 0 })
    const found = await adapter.credentials.findByHashedSecret('hash-secret-5', 'api-key', {})
    expect(found?.revokedAt).toBe(0)
  })
})
