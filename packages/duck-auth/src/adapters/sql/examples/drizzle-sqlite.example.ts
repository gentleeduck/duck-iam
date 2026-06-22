// @ts-nocheck
/**
 * Reference Drizzle ORM (SQLite via better-sqlite3) implementation of
 * the AuthSqlBridge contract. Drop into your project, install the peerDeps,
 * swap in your own column / schema customizations, then hand the bridge
 * to `authCreateSqlStores`.
 *
 * NOT compiled by tsdown (skipped via the `.example.ts` suffix +
 * `@ts-nocheck` so consumers without `drizzle-orm` / `better-sqlite3`
 * installed don't break their build). Copy the file, do not import it.
 *
 * Required peerDeps (consumer side):
 *   bun add drizzle-orm better-sqlite3
 *   bun add -D drizzle-kit @types/better-sqlite3
 *
 * Differences from the pg / mysql flavours:
 *   - SQLite stores all integers (including bigints) as INTEGER. The
 *     mode-`number` Drizzle column already handles the JS-side
 *     conversion.
 *   - JSON queries use the JSON1 extension's `json_extract`. JSON1 is
 *     bundled with every modern SQLite (>= 3.38).
 *   - `RETURNING` works in SQLite >= 3.35 - same idiom as pg here.
 */

import type { AuthSqlBridge } from '@gentleduck/auth/adapters/sql'
import { and, eq, isNull, lt, sql } from 'drizzle-orm'
import type { BetterSQLite3Database } from 'drizzle-orm/better-sqlite3'
import { index, integer, sqliteTable, text } from 'drizzle-orm/sqlite-core'

// ---------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------

export const authIdentitiesTable = sqliteTable(
  'auth_identities',
  {
    id: text('id').primaryKey(),
    tenantId: text('tenant_id'),
    profile: text('profile'),
    providers: text('providers').notNull().default('[]'),
    version: integer('version').notNull().default(1),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
    deletedAt: integer('deleted_at'),
  },
  (t) => ({
    tenantIdx: index('auth_identities_tenant').on(t.tenantId),
    deletedAtIdx: index('auth_identities_deleted_at').on(t.deletedAt),
  }),
)

export const authCredentialsTable = sqliteTable(
  'auth_credentials',
  {
    id: text('id').primaryKey(),
    identityId: text('identity_id').notNull(),
    tenantId: text('tenant_id'),
    kind: text('kind').notNull(),
    secret: text('secret').notNull(),
    metadata: text('metadata'),
    version: integer('version').notNull().default(1),
    createdAt: integer('created_at').notNull(),
    lastUsedAt: integer('last_used_at'),
    expiresAt: integer('expires_at'),
    revokedAt: integer('revoked_at'),
  },
  (t) => ({
    identityIdx: index('auth_credentials_identity').on(t.identityId),
    // Bridge contract: findByHashedSecret(kind, secret) is O(1).
    kindSecretIdx: index('auth_credentials_kind_secret').on(t.kind, t.secret),
    tenantIdx: index('auth_credentials_tenant').on(t.tenantId),
  }),
)

export const authSessionsTable = sqliteTable(
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
    createdAt: integer('created_at').notNull(),
    rotatedAt: integer('rotated_at').notNull(),
    expiresAt: integer('expires_at').notNull(),
    absoluteExpiresAt: integer('absolute_expires_at').notNull(),
    fresh: integer('fresh').notNull(),
    actingAs: text('acting_as'),
  },
  (t) => ({
    identityIdx: index('auth_sessions_identity').on(t.identityId),
    expiresIdx: index('auth_sessions_expires').on(t.expiresAt),
    absoluteExpiresIdx: index('auth_sessions_absolute_expires').on(t.absoluteExpiresAt),
  }),
)

// ---------------------------------------------------------------------
// Bridge factory
// ---------------------------------------------------------------------

export function authCreateDrizzleSqliteBridge(db: BetterSQLite3Database): AuthSqlBridge {
  function tenantWhere<T extends { tenantId: unknown }>(table: T, tenantId: string | undefined) {
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
        // Tenant-scope: null tenant_id rows are "global identities"
        // reachable from any tenant, matching findById's semantics.
        const rows = await db.all(
          sql`select * from ${authIdentitiesTable}
              where json_extract(profile, '$.email') = ${email}
                and deleted_at is null
                and (tenant_id is null or ${tenantId ?? null} is null or tenant_id = ${tenantId ?? null})
              limit 1`,
        )
        return (rows[0] as never) ?? null
      },
      findByProviderSub: async (providerId, sub, tenantId) => {
        // json_each over providers; matches null-sub links and treats
        // null tenant_id rows as global (matches findById's semantics).
        const rows = await db.all(
          sql`select i.* from ${authIdentitiesTable} i, json_each(i.providers) j
              where json_extract(j.value, '$.providerId') = ${providerId}
                and (
                  json_extract(j.value, '$.providerSub') = ${sub}
                  or (${sub ?? null} is null and json_extract(j.value, '$.providerSub') is null)
                )
                and i.deleted_at is null
                and (i.tenant_id is null or ${tenantId ?? null} is null or i.tenant_id = ${tenantId ?? null})
              limit 1`,
        )
        return (rows[0] as never) ?? null
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
        await db.delete(authIdentitiesTable).where(and(eq(authIdentitiesTable.id, id), tenantWhere(authIdentitiesTable, tenantId)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt, tenantId) => {
        // Read-modify-write idempotency; not race-safe under concurrent
        // callbacks (wrap in `BEGIN IMMEDIATE` if needed).
        const rows = await db
          .select({ providers: authIdentitiesTable.providers })
          .from(authIdentitiesTable)
          .where(and(eq(authIdentitiesTable.id, identityId), tenantWhere(authIdentitiesTable, tenantId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        const arr = JSON.parse(cur.providers) as Array<{ providerId: string; providerSub?: string; addedAt: number }>
        const exists = arr.some(
          (p) => p.providerId === providerId && (providerSub === undefined || p.providerSub === providerSub),
        )
        if (exists) return
        arr.push({ providerId, providerSub, addedAt })
        await db
          .update(authIdentitiesTable)
          .set({ providers: JSON.stringify(arr) })
          .where(and(eq(authIdentitiesTable.id, identityId), tenantWhere(authIdentitiesTable, tenantId)))
      },
      deleteProviderLink: async (identityId, providerId, tenantId) => {
        const rows = await db
          .select({ providers: authIdentitiesTable.providers })
          .from(authIdentitiesTable)
          .where(and(eq(authIdentitiesTable.id, identityId), tenantWhere(authIdentitiesTable, tenantId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        const arr = JSON.parse(cur.providers) as Array<{ providerId: string }>
        const next = arr.filter((p) => p.providerId !== providerId)
        await db
          .update(authIdentitiesTable)
          .set({ providers: JSON.stringify(next) })
          .where(and(eq(authIdentitiesTable.id, identityId), tenantWhere(authIdentitiesTable, tenantId)))
      },
      merge: async (survivorId, dupId, tenantId) => {
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
        // Use `!== undefined` so empty-string tenant ids are honored
        // (truthy `tenantId ?` would drop the filter for '' and leak
        // across tenants).
        const where = [
          eq(authCredentialsTable.identityId, identityId),
          ...(kind !== undefined ? [eq(authCredentialsTable.kind, kind)] : []),
          ...(tenantId !== undefined ? [eq(authCredentialsTable.tenantId, tenantId)] : []),
        ]
        return db
          .select()
          .from(authCredentialsTable)
          .where(and(...where))
      },
      findByProviderSub: async (provider, sub, _tenantId) => {
        const rows = await db.all(
          sql`select * from ${authCredentialsTable}
              where json_extract(metadata, '$.provider') = ${provider}
                and json_extract(metadata, '$.sub') = ${sub}
              limit 1`,
        )
        return (rows[0] as never) ?? null
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
        const result = await db.delete(authSessionsTable).where(lt(authSessionsTable.absoluteExpiresAt, now)).returning()
        return result.length
      },
    },
  }
}

// ---------------------------------------------------------------------
// Wire-up (replace with your own AuthEngine config)
// ---------------------------------------------------------------------
//
// import Database from 'better-sqlite3'
// import { drizzle } from 'drizzle-orm/better-sqlite3'
// import { authCreateSqlStores } from '@gentleduck/auth/adapters/sql'
//
// const sqlite = new Database(process.env.DATABASE_PATH ?? 'auth.sqlite')
// const db = drizzle(sqlite, { schema: { authIdentitiesTable, authCredentialsTable, authSessionsTable } })
// const bridge = authCreateDrizzleSqliteBridge(db)
// const stores = authCreateSqlStores<MyProfile>(bridge)
//
// new AuthEngine({ stores, ... })
