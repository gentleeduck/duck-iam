import { createRequire } from 'node:module'
import { and, eq, isNull, lt, sql } from 'drizzle-orm'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import { bigint, index, integer, type PgColumn, pgTable, text } from 'drizzle-orm/pg-core'

const lazyRequire = createRequire(import.meta.url)

import { createSqlAuthStores, type SqlBridge } from '../../sql'

interface NodePgPoolLike {
  connect: () => Promise<unknown>
  query: (...args: unknown[]) => unknown
}

function isNodePgDatabase(input: NodePgPoolLike | NodePgDatabase): input is NodePgDatabase {
  return typeof (input as NodePgDatabase).select === 'function'
}

// ---------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------

export const identitiesTable = pgTable(
  'auth_identities',
  {
    id: text('id').primaryKey(),
    tenantId: text('tenant_id'),
    profile: text('profile'),
    providers: text('providers').notNull().default('[]'),
    version: integer('version').notNull().default(1),
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull(),
    deletedAt: bigint('deleted_at', { mode: 'number' }),
  },
  (t) => [index('auth_identities_tenant').on(t.tenantId), index('auth_identities_deleted_at').on(t.deletedAt)],
)

export const credentialsTable = pgTable(
  'auth_credentials',
  {
    id: text('id').primaryKey(),
    identityId: text('identity_id').notNull(),
    tenantId: text('tenant_id'),
    kind: text('kind').notNull(),
    secret: text('secret').notNull(),
    metadata: text('metadata'),
    version: integer('version').notNull().default(1),
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    lastUsedAt: bigint('last_used_at', { mode: 'number' }),
    expiresAt: bigint('expires_at', { mode: 'number' }),
    revokedAt: bigint('revoked_at', { mode: 'number' }),
  },
  (t) => [
    index('auth_credentials_identity').on(t.identityId),
    index('auth_credentials_kind_secret').on(t.kind, t.secret),
    index('auth_credentials_tenant').on(t.tenantId),
  ],
)

export const sessionsTable = pgTable(
  'auth_sessions',
  {
    id: text('id').primaryKey(),
    identityId: text('identity_id'),
    tenantId: text('tenant_id'),
    kind: text('kind').notNull(),
    aal: integer('aal').notNull(),
    factors: text('factors').notNull().default('[]'),
    csrfHash: text('csrf_hash'),
    ip: text('ip'),
    userAgent: text('user_agent'),
    fingerprint: text('fingerprint'),
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    rotatedAt: bigint('rotated_at', { mode: 'number' }).notNull(),
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    absoluteExpiresAt: bigint('absolute_expires_at', { mode: 'number' }).notNull(),
    fresh: integer('fresh').notNull(),
    actingAs: text('acting_as'),
  },
  (t) => [
    index('auth_sessions_identity').on(t.identityId),
    index('auth_sessions_expires').on(t.expiresAt),
    index('auth_sessions_absolute_expires').on(t.absoluteExpiresAt),
  ],
)

// ---------------------------------------------------------------------
// Bridge factory
// ---------------------------------------------------------------------

export function createDrizzlePgAuthBridge<const TSchema extends Record<string, unknown>>(
  db: NodePgDatabase<TSchema>,
): SqlBridge.IBridge {
  /** Helper: scope a where clause by tenantId; null tenant matches the row's NULL. */
  function tenantWhere<T extends { tenantId: PgColumn }>(table: T, tenantId: string | undefined) {
    return tenantId === undefined ? undefined : eq(table.tenantId, tenantId)
  }

  return {
    identities: {
      findById: async (id, tenantId) => {
        const rows = await db
          .select()
          .from(identitiesTable)
          .where(and(eq(identitiesTable.id, id), isNull(identitiesTable.deletedAt)))
          .limit(1)
        const row = rows[0]
        if (!row) return null
        if (tenantId !== undefined && row.tenantId !== tenantId && row.tenantId !== null) return null
        return row
      },
      findByEmail: async (email, tenantId) => {
        // Profile is JSON-encoded; cheapest portable extraction is server-side json operators.
        // Tenant-scope: null tenant_id rows are "global identities"
        // reachable from any tenant, matching findById's semantics.
        const rows = await db.execute(
          sql`select * from ${identitiesTable}
              where (profile::jsonb)->>'email' = ${email}
                and deleted_at is null
                and (tenant_id is null or ${tenantId ?? null}::text is null or tenant_id = ${tenantId ?? null}::text)
              limit 1`,
        )
        return (rows.rows[0] as never) ?? null
      },
      findByProviderSub: async (providerId, sub, tenantId) => {
        // `${...}` binds as $N; `.raw` would be SQL injection.
        const matchPattern = JSON.stringify([{ providerId, providerSub: sub }])
        const rows = await db.execute(
          sql`select * from ${identitiesTable}
              where (providers::jsonb) @> ${matchPattern}::jsonb
                and deleted_at is null
                and (tenant_id is null or ${tenantId ?? null}::text is null or tenant_id = ${tenantId ?? null}::text)
              limit 1`,
        )
        return (rows.rows[0] as never) ?? null
      },
      insert: async (row) => {
        await db.insert(identitiesTable).values(row)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const result = await db
          .update(identitiesTable)
          .set(patch as never)
          .where(
            and(
              eq(identitiesTable.id, id),
              eq(identitiesTable.version, expectedVersion),
              tenantWhere(identitiesTable, tenantId),
            ),
          )
          .returning()
        return result[0] ?? null
      },
      softDelete: async (id, deletedAt, tenantId) => {
        await db
          .update(identitiesTable)
          .set({ deletedAt })
          .where(and(eq(identitiesTable.id, id), tenantWhere(identitiesTable, tenantId)))
      },
      restore: async (id, tenantId) => {
        const result = await db
          .update(identitiesTable)
          .set({ deletedAt: null })
          .where(and(eq(identitiesTable.id, id), tenantWhere(identitiesTable, tenantId)))
          .returning()
        return result[0] ?? null
      },
      erase: async (id, tenantId) => {
        await db.delete(credentialsTable).where(eq(credentialsTable.identityId, id))
        await db.delete(sessionsTable).where(eq(sessionsTable.identityId, id))
        await db.delete(identitiesTable).where(and(eq(identitiesTable.id, id), tenantWhere(identitiesTable, tenantId)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt, tenantId) => {
        const newLink = JSON.stringify([{ providerId, providerSub, addedAt }])
        await db.execute(
          sql`update ${identitiesTable}
              set providers = (
                select jsonb_agg(distinct elem)
                from jsonb_array_elements(providers::jsonb || ${newLink}::jsonb) elem
              )::text
              where id = ${identityId}
                and (${tenantId ?? null}::text is null or tenant_id = ${tenantId ?? null}::text)`,
        )
      },
      deleteProviderLink: async (identityId, providerId, tenantId) => {
        await db.execute(
          sql`update ${identitiesTable}
              set providers = (
                select coalesce(jsonb_agg(elem), '[]'::jsonb)::text
                from jsonb_array_elements(providers::jsonb) elem
                where (elem->>'providerId') != ${providerId}
              )
              where id = ${identityId}
                and (${tenantId ?? null}::text is null or tenant_id = ${tenantId ?? null}::text)`,
        )
      },
      merge: async (survivorId, dupId, tenantId) => {
        // Cascade is tenant-scoped: cross-tenant merge attempts are no-ops.
        await db
          .update(credentialsTable)
          .set({ identityId: survivorId })
          .where(and(eq(credentialsTable.identityId, dupId), tenantWhere(credentialsTable, tenantId)))
        await db
          .update(sessionsTable)
          .set({ identityId: survivorId })
          .where(and(eq(sessionsTable.identityId, dupId), tenantWhere(sessionsTable, tenantId)))
        await db
          .delete(identitiesTable)
          .where(and(eq(identitiesTable.id, dupId), tenantWhere(identitiesTable, tenantId)))
      },
    },
    credentials: {
      findById: async (id, tenantId) => {
        const rows = await db
          .select()
          .from(credentialsTable)
          .where(and(eq(credentialsTable.id, id), tenantWhere(credentialsTable, tenantId)))
          .limit(1)
        return rows[0] ?? null
      },
      listByIdentity: async (identityId, kind, tenantId) => {
        const where = [
          eq(credentialsTable.identityId, identityId),
          ...(kind ? [eq(credentialsTable.kind, kind)] : []),
          ...(tenantId ? [eq(credentialsTable.tenantId, tenantId)] : []),
        ]
        return db
          .select()
          .from(credentialsTable)
          .where(and(...where))
      },
      findByProviderSub: async (provider, sub, _tenantId) => {
        const rows = await db.execute(
          sql`select * from ${credentialsTable}
              where (metadata::jsonb)->>'provider' = ${provider}
                and (metadata::jsonb)->>'sub' = ${sub}
              limit 1`,
        )
        return (rows.rows[0] as never) ?? null
      },
      findByHashedSecret: async (secretHash, kind, tenantId) => {
        const rows = await db
          .select()
          .from(credentialsTable)
          .where(
            and(
              eq(credentialsTable.secret, secretHash),
              eq(credentialsTable.kind, kind),
              tenantWhere(credentialsTable, tenantId),
            ),
          )
          .limit(1)
        return rows[0] ?? null
      },
      insert: async (row) => {
        await db.insert(credentialsTable).values(row)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const result = await db
          .update(credentialsTable)
          .set(patch as never)
          .where(
            and(
              eq(credentialsTable.id, id),
              eq(credentialsTable.version, expectedVersion),
              tenantWhere(credentialsTable, tenantId),
            ),
          )
          .returning()
        return result[0] ?? null
      },
      revoke: async (id, revokedAt, tenantId) => {
        await db
          .update(credentialsTable)
          .set({ revokedAt })
          .where(and(eq(credentialsTable.id, id), tenantWhere(credentialsTable, tenantId)))
      },
      delete: async (id, tenantId) => {
        await db
          .delete(credentialsTable)
          .where(and(eq(credentialsTable.id, id), tenantWhere(credentialsTable, tenantId)))
      },
      deleteByKind: async (identityId, kind, tenantId) => {
        await db
          .delete(credentialsTable)
          .where(
            and(
              eq(credentialsTable.identityId, identityId),
              eq(credentialsTable.kind, kind),
              tenantWhere(credentialsTable, tenantId),
            ),
          )
      },
    },
    sessions: {
      insert: async (row) => {
        await db.insert(sessionsTable).values(row)
      },
      findByHash: async (sidHash) => {
        const rows = await db.select().from(sessionsTable).where(eq(sessionsTable.id, sidHash)).limit(1)
        return rows[0] ?? null
      },
      update: async (id, patch) => {
        const result = await db
          .update(sessionsTable)
          .set(patch as never)
          .where(eq(sessionsTable.id, id))
          .returning()
        return result[0] ?? null
      },
      delete: async (id) => {
        await db.delete(sessionsTable).where(eq(sessionsTable.id, id))
      },
      listByIdentity: async (identityId) => {
        return db.select().from(sessionsTable).where(eq(sessionsTable.identityId, identityId))
      },
      deleteAllForIdentity: async (identityId) => {
        await db.delete(sessionsTable).where(eq(sessionsTable.identityId, identityId))
      },
      deleteExpired: async (now) => {
        const result = await db.delete(sessionsTable).where(lt(sessionsTable.absoluteExpiresAt, now)).returning()
        return result.length
      },
    },
  }
}

/**
 * Storage helper folding `Pool -> drizzle -> bridge -> stores`. Accepts connection string, `pg.Pool`, or `NodePgDatabase`.
 *
 * @template Profile - Identity profile shape.
 */
export function drizzlePgStorage<const Profile>(
  input: string | NodePgPoolLike | NodePgDatabase,
): ReturnType<typeof createSqlAuthStores<Profile>> {
  // Lazy-require to avoid a hard runtime dep when consumers wire the
  // bridge themselves; `pg` + `drizzle-orm` are optional peerDeps.
  let db: NodePgDatabase
  if (typeof input === 'string') {
    const { Pool } = lazyRequire('pg')
    const { drizzle } = lazyRequire('drizzle-orm/node-postgres')
    db = drizzle(new Pool({ connectionString: input })) as unknown as NodePgDatabase
  } else {
    if (isNodePgDatabase(input)) {
      db = input
    } else {
      const { drizzle } = lazyRequire('drizzle-orm/node-postgres')
      db = drizzle(input)
    }
  }
  return createSqlAuthStores<Profile>(createDrizzlePgAuthBridge(db))
}
