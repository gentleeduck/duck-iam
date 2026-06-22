import { createRequire } from 'node:module'
import { and, eq, isNull, lt, sql } from 'drizzle-orm'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import { bigint, index, integer, type PgColumn, pgTable, text } from 'drizzle-orm/pg-core'

const lazyRequire = createRequire(import.meta.url)

import { type AuthSqlBridge, authCreateSqlStores } from '../../sql'

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

export const authIdentitiesTable = pgTable(
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

export const authCredentialsTable = pgTable(
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

export const authSessionsTable = pgTable(
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

export function authCreateDrizzlePgBridge<const TSchema extends Record<string, unknown>>(
  db: NodePgDatabase<TSchema>,
): AuthSqlBridge.IBridge {
  /** Helper: scope a where clause by tenantId; null tenant matches the row's NULL. */
  function tenantWhere<T extends { tenantId: PgColumn }>(table: T, tenantId: string | undefined) {
    return tenantId === undefined ? undefined : eq(table.tenantId, tenantId)
  }

  return {
    identities: {
      findById: async (id, tenantId) => {
        const rows = await db
          .select()
          .from(authIdentitiesTable)
          .where(and(eq(authIdentitiesTable.id, id), isNull(authIdentitiesTable.deletedAt)))
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
          sql`select * from ${authIdentitiesTable}
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
          sql`select * from ${authIdentitiesTable}
              where (providers::jsonb) @> ${matchPattern}::jsonb
                and deleted_at is null
                and (tenant_id is null or ${tenantId ?? null}::text is null or tenant_id = ${tenantId ?? null}::text)
              limit 1`,
        )
        return (rows.rows[0] as never) ?? null
      },
      insert: async (row) => {
        await db.insert(authIdentitiesTable).values(row)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const result = await db
          .update(authIdentitiesTable)
          .set(patch as never)
          .where(
            and(
              eq(authIdentitiesTable.id, id),
              eq(authIdentitiesTable.version, expectedVersion),
              tenantWhere(authIdentitiesTable, tenantId),
            ),
          )
          .returning()
        return result[0] ?? null
      },
      softDelete: async (id, deletedAt, tenantId) => {
        await db
          .update(authIdentitiesTable)
          .set({ deletedAt })
          .where(and(eq(authIdentitiesTable.id, id), tenantWhere(authIdentitiesTable, tenantId)))
      },
      restore: async (id, tenantId) => {
        const result = await db
          .update(authIdentitiesTable)
          .set({ deletedAt: null })
          .where(and(eq(authIdentitiesTable.id, id), tenantWhere(authIdentitiesTable, tenantId)))
          .returning()
        return result[0] ?? null
      },
      erase: async (id, tenantId) => {
        await db.delete(authCredentialsTable).where(eq(authCredentialsTable.identityId, id))
        await db.delete(authSessionsTable).where(eq(authSessionsTable.identityId, id))
        await db
          .delete(authIdentitiesTable)
          .where(and(eq(authIdentitiesTable.id, id), tenantWhere(authIdentitiesTable, tenantId)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt, tenantId) => {
        const newLink = JSON.stringify([{ providerId, providerSub, addedAt }])
        await db.execute(
          sql`update ${authIdentitiesTable}
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
          sql`update ${authIdentitiesTable}
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
          .update(authCredentialsTable)
          .set({ identityId: survivorId })
          .where(and(eq(authCredentialsTable.identityId, dupId), tenantWhere(authCredentialsTable, tenantId)))
        await db
          .update(authSessionsTable)
          .set({ identityId: survivorId })
          .where(and(eq(authSessionsTable.identityId, dupId), tenantWhere(authSessionsTable, tenantId)))
        await db
          .delete(authIdentitiesTable)
          .where(and(eq(authIdentitiesTable.id, dupId), tenantWhere(authIdentitiesTable, tenantId)))
      },
    },
    credentials: {
      findById: async (id, tenantId) => {
        const rows = await db
          .select()
          .from(authCredentialsTable)
          .where(and(eq(authCredentialsTable.id, id), tenantWhere(authCredentialsTable, tenantId)))
          .limit(1)
        return rows[0] ?? null
      },
      listByIdentity: async (identityId, kind, tenantId) => {
        const where = [
          eq(authCredentialsTable.identityId, identityId),
          ...(kind ? [eq(authCredentialsTable.kind, kind)] : []),
          ...(tenantId ? [eq(authCredentialsTable.tenantId, tenantId)] : []),
        ]
        return db
          .select()
          .from(authCredentialsTable)
          .where(and(...where))
      },
      findByProviderSub: async (provider, sub, _tenantId) => {
        const rows = await db.execute(
          sql`select * from ${authCredentialsTable}
              where (metadata::jsonb)->>'provider' = ${provider}
                and (metadata::jsonb)->>'sub' = ${sub}
              limit 1`,
        )
        return (rows.rows[0] as never) ?? null
      },
      findByHashedSecret: async (secretHash, kind, tenantId) => {
        const rows = await db
          .select()
          .from(authCredentialsTable)
          .where(
            and(
              eq(authCredentialsTable.secret, secretHash),
              eq(authCredentialsTable.kind, kind),
              tenantWhere(authCredentialsTable, tenantId),
            ),
          )
          .limit(1)
        return rows[0] ?? null
      },
      insert: async (row) => {
        await db.insert(authCredentialsTable).values(row)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const result = await db
          .update(authCredentialsTable)
          .set(patch as never)
          .where(
            and(
              eq(authCredentialsTable.id, id),
              eq(authCredentialsTable.version, expectedVersion),
              tenantWhere(authCredentialsTable, tenantId),
            ),
          )
          .returning()
        return result[0] ?? null
      },
      revoke: async (id, revokedAt, tenantId) => {
        await db
          .update(authCredentialsTable)
          .set({ revokedAt })
          .where(and(eq(authCredentialsTable.id, id), tenantWhere(authCredentialsTable, tenantId)))
      },
      delete: async (id, tenantId) => {
        await db
          .delete(authCredentialsTable)
          .where(and(eq(authCredentialsTable.id, id), tenantWhere(authCredentialsTable, tenantId)))
      },
      deleteByKind: async (identityId, kind, tenantId) => {
        await db
          .delete(authCredentialsTable)
          .where(
            and(
              eq(authCredentialsTable.identityId, identityId),
              eq(authCredentialsTable.kind, kind),
              tenantWhere(authCredentialsTable, tenantId),
            ),
          )
      },
    },
    sessions: {
      insert: async (row) => {
        await db.insert(authSessionsTable).values(row)
      },
      findByHash: async (sidHash) => {
        const rows = await db.select().from(authSessionsTable).where(eq(authSessionsTable.id, sidHash)).limit(1)
        return rows[0] ?? null
      },
      update: async (id, patch) => {
        const result = await db
          .update(authSessionsTable)
          .set(patch as never)
          .where(eq(authSessionsTable.id, id))
          .returning()
        return result[0] ?? null
      },
      delete: async (id) => {
        await db.delete(authSessionsTable).where(eq(authSessionsTable.id, id))
      },
      listByIdentity: async (identityId) => {
        return db.select().from(authSessionsTable).where(eq(authSessionsTable.identityId, identityId))
      },
      deleteAllForIdentity: async (identityId) => {
        await db.delete(authSessionsTable).where(eq(authSessionsTable.identityId, identityId))
      },
      deleteExpired: async (now) => {
        const result = await db
          .delete(authSessionsTable)
          .where(lt(authSessionsTable.absoluteExpiresAt, now))
          .returning()
        return result.length
      },
    },
  }
}

/**
 * Storage helper folding `Pool -> drizzle -> bridge -> stores`. Accepts connection string, `pg.Pool`, or `NodePgDatabase`.
 *
 * @template Profile - AuthIdentity profile shape.
 */
export function authDrizzlePgStorage<const Profile>(
  input: string | NodePgPoolLike | NodePgDatabase,
): ReturnType<typeof authCreateSqlStores<Profile>> {
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
  return authCreateSqlStores<Profile>(authCreateDrizzlePgBridge(db))
}
