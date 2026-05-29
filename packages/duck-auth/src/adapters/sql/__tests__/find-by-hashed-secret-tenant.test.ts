import { beforeEach, describe, expect, it } from 'vitest'
import { createSqlAuthStores, SqlBridge } from '../index'

/**
 * Bridge-level tenant filter parity tests for createSqlAuthStores.
 *
 * Mirrors packages/duck-auth/src/adapters/memory/__tests__/
 * find-by-hashed-secret-tenant.test.ts so any future SQL/memory drift
 * is caught here, not in production.
 */

function makeBridge(): SqlBridge.IBridge {
  const credentials = new Map<string, SqlBridge.ICredentialRow>()
  const identities = new Map<string, SqlBridge.IIdentityRow>()
  return {
    identities: {
      findById: async () => null,
      findByEmail: async () => null,
      findByProviderSub: async () => null,
      insert: async (row) => {
        identities.set(row.id, row)
      },
      updateConditional: async () => null,
      softDelete: async () => {},
      restore: async () => null,
      erase: async () => {},
      insertProviderLink: async () => {},
      deleteProviderLink: async () => {},
      merge: async () => {},
    },
    credentials: {
      findById: async (id) => credentials.get(id) ?? null,
      listByIdentity: async () => [],
      findByProviderSub: async () => null,
      findByHashedSecret: async (secretHash, kind, tenantId) => {
        for (const r of credentials.values()) {
          if (r.kind !== kind || r.secret !== secretHash) continue
          if (tenantId !== undefined && r.tenantId !== tenantId && r.tenantId !== null) continue
          return r
        }
        return null
      },
      insert: async (row) => {
        credentials.set(row.id, row)
      },
      updateConditional: async () => null,
      revoke: async () => {},
      delete: async (id) => {
        credentials.delete(id)
      },
      deleteByKind: async () => {},
    },
    sessions: {
      insert: async () => {},
      findByHash: async () => null,
      update: async () => null,
      delete: async () => {},
      listByIdentity: async () => [],
      deleteAllForIdentity: async () => {},
      deleteExpired: async () => 0,
    },
  }
}

describe('createSqlAuthStores.findByHashedSecret tenant filter parity', () => {
  let bridge: SqlBridge.IBridge
  let stores: ReturnType<typeof createSqlAuthStores<{ email: string }>>

  beforeEach(() => {
    bridge = makeBridge()
    stores = createSqlAuthStores<{ email: string }>(bridge)
  })

  it('returns null when ctx.tenantId mismatches the row tenantId', async () => {
    const ident = await stores.identities.create(
      { profile: { email: 'svc@x.com' }, providers: [] },
      { tenantId: 'tenant-A' },
    )
    await stores.credentials.upsert(
      { identityId: ident.id, kind: 'api-key', secret: 'hash-1', tenantId: 'tenant-A' },
      { tenantId: 'tenant-A' },
    )
    const fromTenantB = await stores.credentials.findByHashedSecret('hash-1', 'api-key', {
      tenantId: 'tenant-B',
    })
    expect(fromTenantB).toBeNull()
  })

  it('returns the row when ctx.tenantId matches', async () => {
    const ident = await stores.identities.create(
      { profile: { email: 'svc@x.com' }, providers: [] },
      { tenantId: 'tenant-A' },
    )
    await stores.credentials.upsert(
      { identityId: ident.id, kind: 'api-key', secret: 'hash-2', tenantId: 'tenant-A' },
      { tenantId: 'tenant-A' },
    )
    const fromTenantA = await stores.credentials.findByHashedSecret('hash-2', 'api-key', {
      tenantId: 'tenant-A',
    })
    expect(fromTenantA?.identityId).toBe(ident.id)
  })

  it('returns global (no tenantId) rows from any tenant scope', async () => {
    const ident = await stores.identities.create({ profile: { email: 'global@x.com' }, providers: [] }, {})
    await stores.credentials.upsert({ identityId: ident.id, kind: 'api-key', secret: 'hash-3' }, {})
    const fromTenantA = await stores.credentials.findByHashedSecret('hash-3', 'api-key', {
      tenantId: 'tenant-A',
    })
    expect(fromTenantA?.identityId).toBe(ident.id)
  })

  it('returns tenant-scoped row when ctx tenantId is undefined (global search)', async () => {
    const ident = await stores.identities.create(
      { profile: { email: 'svc@x.com' }, providers: [] },
      { tenantId: 'tenant-A' },
    )
    await stores.credentials.upsert(
      { identityId: ident.id, kind: 'api-key', secret: 'hash-4', tenantId: 'tenant-A' },
      { tenantId: 'tenant-A' },
    )
    const found = await stores.credentials.findByHashedSecret('hash-4', 'api-key', {})
    expect(found?.identityId).toBe(ident.id)
  })

  it('upsert inherits ctx.tenantId when input.tenantId is unset', async () => {
    const ident = await stores.identities.create(
      { profile: { email: 'i@x.com' }, providers: [] },
      { tenantId: 'tenant-A' },
    )
    await stores.credentials.upsert(
      { identityId: ident.id, kind: 'api-key', secret: 'hash-5' },
      { tenantId: 'tenant-A' },
    )
    const fromTenantA = await stores.credentials.findByHashedSecret('hash-5', 'api-key', {
      tenantId: 'tenant-A',
    })
    expect(fromTenantA?.tenantId).toBe('tenant-A')
    const fromTenantB = await stores.credentials.findByHashedSecret('hash-5', 'api-key', {
      tenantId: 'tenant-B',
    })
    expect(fromTenantB).toBeNull()
  })
})
