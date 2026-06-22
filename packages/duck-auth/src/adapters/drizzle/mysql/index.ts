// @ts-nocheck
/**
 * Reference Drizzle ORM (MySQL / MariaDB) implementation of the AuthSqlBridge
 * contract. Drop into your project, install the peerDeps, swap in your
 * own column / schema customizations, then hand the bridge to
 * `authCreateSqlStores`.
 *
 * NOT compiled by tsdown (skipped via the `.example.ts` suffix +
 * `@ts-nocheck` so consumers without `drizzle-orm` / `mysql2` installed
 * don't break their build). Copy the file, do not import it.
 *
 * Required peerDeps (consumer side):
 *   bun add drizzle-orm mysql2
 *   bun add -D drizzle-kit
 *
 * Differences from the pg flavour:
 *   - `JSON_EXTRACT(col, '$.key')` replaces pg's `(col::jsonb)->>'key'`.
 *   - MySQL does not implement `RETURNING`; updates that need the new
 *     row issue a separate `SELECT` afterwards.
 *   - AuthProvider-link upserts are done client-side (parse JSON, splice,
 *     re-write) for portability across MySQL 5.7 / 8.x / MariaDB.
 */

import { createRequire } from 'node:module'
import { and, eq, isNull, lt, sql } from 'drizzle-orm'

const lazyRequire = createRequire(import.meta.url)

import { bigint, index, int, mysqlTable, text, varchar } from 'drizzle-orm/mysql-core'
import type { MySql2Database } from 'drizzle-orm/mysql2'
import { authCreateSqlStores, type AuthSqlBridge } from '../../sql'
import { authParseProviderLinks } from '../_parsers'

// ---------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------

export const authIdentitiesTable = mysqlTable(
  'auth_identities',
  {
    id: varchar('id', { length: 64 }).primaryKey(),
    tenantId: varchar('tenant_id', { length: 64 }),
    profile: text('profile'),
    providers: text('providers').notNull().default('[]'),
    version: int('version').notNull().default(1),
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull(),
    deletedAt: bigint('deleted_at', { mode: 'number' }),
  },
  (t) => ({
    tenantIdx: index('auth_identities_tenant').on(t.tenantId),
    deletedAtIdx: index('auth_identities_deleted_at').on(t.deletedAt),
  }),
)

export const authCredentialsTable = mysqlTable(
  'auth_credentials',
  {
    id: varchar('id', { length: 64 }).primaryKey(),
    identityId: varchar('identity_id', { length: 64 }).notNull(),
    tenantId: varchar('tenant_id', { length: 64 }),
    kind: varchar('kind', { length: 32 }).notNull(),
    // 512 covers Argon2id PHC strings at any sensible cost parameter.
    secret: varchar('secret', { length: 512 }).notNull(),
    metadata: text('metadata'),
    version: int('version').notNull().default(1),
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    lastUsedAt: bigint('last_used_at', { mode: 'number' }),
    expiresAt: bigint('expires_at', { mode: 'number' }),
    revokedAt: bigint('revoked_at', { mode: 'number' }),
  },
  (t) => ({
    identityIdx: index('auth_credentials_identity').on(t.identityId),
    // Bridge contract: findByHashedSecret(kind, secret) is O(1).
    kindSecretIdx: index('auth_credentials_kind_secret').on(t.kind, t.secret),
    tenantIdx: index('auth_credentials_tenant').on(t.tenantId),
  }),
)

export const authSessionsTable = mysqlTable(
  'auth_sessions',
  {
    id: varchar('id', { length: 64 }).primaryKey(),
    identityId: varchar('identity_id', { length: 64 }),
    tenantId: varchar('tenant_id', { length: 64 }),
    kind: varchar('kind', { length: 32 }).notNull(),
    aal: int('aal').notNull(),
    factors: text('factors').notNull().default('[]'),
    csrfHash: varchar('csrf_hash', { length: 128 }),
    ip: varchar('ip', { length: 45 }),
    userAgent: text('user_agent'),
    fingerprint: varchar('fingerprint', { length: 128 }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    rotatedAt: bigint('rotated_at', { mode: 'number' }).notNull(),
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    absoluteExpiresAt: bigint('absolute_expires_at', { mode: 'number' }).notNull(),
    fresh: int('fresh').notNull(),
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

export function authCreateDrizzleMysqlBridge(db: MySql2Database): AuthSqlBridge {
  function tenantWhere<T extends { tenantId: unknown }>(table: T, tenantId: string | undefined) {
    return tenantId === undefined ? undefined : eq(table.tenantId, tenantId)
  }

  /** MySQL has no RETURNING; re-select the row after an update. */
  async function reselect<T>(table: never, id: string): Promise<T | null> {
    const rows = await db.select().from(table).where(eq(table.id, id)).limit(1)
    return (rows[0] as T) ?? null
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
        const rows = await db.execute(
          sql`select * from ${authIdentitiesTable}
              where JSON_EXTRACT(profile, '$.email') = ${email}
                and deleted_at is null
                and (tenant_id is null or ${tenantId ?? null} is null or tenant_id = ${tenantId ?? null})
              limit 1`,
        )
        return (rows[0] as never) ?? null
      },
      findByProviderSub: async (providerId, sub, tenantId) => {
        // MySQL's JSON_CONTAINS is the portable check for "has element X".
        const needle = JSON.stringify({ providerId, providerSub: sub })
        const rows = await db.execute(
          sql`select * from ${authIdentitiesTable}
              where JSON_CONTAINS(providers, ${needle})
                and deleted_at is null
                and (tenant_id is null or ${tenantId ?? null} is null or tenant_id = ${tenantId ?? null})
              limit 1`,
        )
        return (rows[0] as never) ?? null
      },
      insert: async (row) => {
        await db.insert(authIdentitiesTable).values(row)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const r = await db
          .update(authIdentitiesTable)
          .set(patch as never)
          .where(
            and(
              eq(authIdentitiesTable.id, id),
              eq(authIdentitiesTable.version, expectedVersion),
              tenantWhere(authIdentitiesTable, tenantId),
            ),
          )
        // mysql2 returns `{ rowsAffected }`; fall back to reselect on success.
        if ((r as { rowsAffected?: number }).rowsAffected === 0) return null
        return reselect(authIdentitiesTable, id)
      },
      softDelete: async (id, deletedAt, tenantId) => {
        await db
          .update(authIdentitiesTable)
          .set({ deletedAt })
          .where(and(eq(authIdentitiesTable.id, id), tenantWhere(authIdentitiesTable, tenantId)))
      },
      restore: async (id, tenantId) => {
        await db
          .update(authIdentitiesTable)
          .set({ deletedAt: null })
          .where(and(eq(authIdentitiesTable.id, id), tenantWhere(authIdentitiesTable, tenantId)))
        return reselect(authIdentitiesTable, id)
      },
      erase: async (id, tenantId) => {
        await db.delete(authCredentialsTable).where(eq(authCredentialsTable.identityId, id))
        await db.delete(authSessionsTable).where(eq(authSessionsTable.identityId, id))
        await db.delete(authIdentitiesTable).where(and(eq(authIdentitiesTable.id, id), tenantWhere(authIdentitiesTable, tenantId)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt, tenantId) => {
        // Portable across MySQL 5.7/8.x; wrap in `SELECT ... FOR UPDATE` if races.
        const rows = await db
          .select()
          .from(authIdentitiesTable)
          .where(and(eq(authIdentitiesTable.id, identityId), tenantWhere(authIdentitiesTable, tenantId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        // authParseProviderLinks fail-safes
        // malformed providers JSON to [] (was: crash on `null` /
        // non-array / `JSON.parse` SyntaxError).
        const arr = authParseProviderLinks(cur.providers)
        const exists = arr.some(
          (p) => p.providerId === providerId && (providerSub === undefined || p.providerSub === providerSub),
        )
        if (exists) return
        arr.push(providerSub === undefined ? { providerId, addedAt } : { providerId, providerSub, addedAt })
        await db
          .update(authIdentitiesTable)
          .set({ providers: JSON.stringify(arr) })
          .where(and(eq(authIdentitiesTable.id, identityId), tenantWhere(authIdentitiesTable, tenantId)))
      },
      deleteProviderLink: async (identityId, providerId, tenantId) => {
        const rows = await db
          .select()
          .from(authIdentitiesTable)
          .where(and(eq(authIdentitiesTable.id, identityId), tenantWhere(authIdentitiesTable, tenantId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        const arr = authParseProviderLinks(cur.providers)
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
        const rows = await db.execute(
          sql`select * from ${authCredentialsTable}
              where JSON_EXTRACT(metadata, '$.provider') = ${provider}
                and JSON_EXTRACT(metadata, '$.sub') = ${sub}
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
        const r = await db
          .update(authCredentialsTable)
          .set(patch as never)
          .where(
            and(
              eq(authCredentialsTable.id, id),
              eq(authCredentialsTable.version, expectedVersion),
              tenantWhere(authCredentialsTable, tenantId),
            ),
          )
        if ((r as { rowsAffected?: number }).rowsAffected === 0) return null
        return reselect(authCredentialsTable, id)
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
        const r = await db
          .update(authSessionsTable)
          .set(patch as never)
          .where(eq(authSessionsTable.id, id))
        if ((r as { rowsAffected?: number }).rowsAffected === 0) return null
        return reselect(authSessionsTable, id)
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
        const r = await db.delete(authSessionsTable).where(lt(authSessionsTable.absoluteExpiresAt, now))
        return (r as { rowsAffected?: number }).rowsAffected ?? 0
      },
    },
  }
}

// ---------------------------------------------------------------------
// Wire-up (replace with your own AuthEngine config)
// ---------------------------------------------------------------------
//
// import { drizzle } from 'drizzle-orm/mysql2'
// import mysql from 'mysql2/promise'
// import { authCreateSqlStores } from '../../sql'
//
// const pool = mysql.createPool({ uri: process.env.DATABASE_URL! })
// const db = drizzle(pool, { schema: { authIdentitiesTable, authCredentialsTable, authSessionsTable }, mode: 'default' })
// const bridge = authCreateDrizzleMysqlBridge(db)
// const stores = authCreateSqlStores<MyProfile>(bridge)
//
// new AuthEngine({ stores, ... })

/**
 * Storage helper folding `mysql2 pool -> drizzle -> bridge -> stores`. Accepts connection string, mysql2 pool, or MySql2Database.
 *
 * @template Profile - AuthIdentity profile shape.
 */
export const authDrizzleMysqlStorage = <Profile = unknown>(
  input: string | MySql2Database | { execute: () => unknown },
): ReturnType<typeof authCreateSqlStores<Profile>> => {
  let db: MySql2Database
  if (typeof input === 'string') {
    const mysql = lazyRequire('mysql2/promise')
    const { drizzle } = lazyRequire('drizzle-orm/mysql2')
    db = drizzle(mysql.createPool(input)) as unknown as MySql2Database
  } else if (
    typeof (input as { execute?: unknown }).execute === 'function' &&
    typeof (input as { query?: unknown }).query !== 'function'
  ) {
    const { drizzle } = lazyRequire('drizzle-orm/mysql2')
    db = drizzle(input as never) as unknown as MySql2Database
  } else {
    db = input as MySql2Database
  }
  return authCreateSqlStores<Profile>(authCreateDrizzleMysqlBridge(db))
}
