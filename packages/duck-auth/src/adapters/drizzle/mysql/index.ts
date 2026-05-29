// @ts-nocheck
/**
 * Reference Drizzle ORM (MySQL / MariaDB) implementation of the SqlBridge
 * contract. Drop into your project, install the peerDeps, swap in your
 * own column / schema customizations, then hand the bridge to
 * `createSqlAuthStores`.
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
 *   - Provider-link upserts are done client-side (parse JSON, splice,
 *     re-write) for portability across MySQL 5.7 / 8.x / MariaDB.
 */

import { createRequire } from 'node:module'
import { and, eq, isNull, lt, sql } from 'drizzle-orm'

const lazyRequire = createRequire(import.meta.url)

import { bigint, index, int, mysqlTable, text, varchar } from 'drizzle-orm/mysql-core'
import type { MySql2Database } from 'drizzle-orm/mysql2'
import { createSqlAuthStores, type SqlBridge } from '../../sql'
import { parseProviderLinks } from '../_parsers'

// ---------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------

export const identitiesTable = mysqlTable(
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

export const credentialsTable = mysqlTable(
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

export const sessionsTable = mysqlTable(
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

export function createDrizzleMysqlAuthBridge(db: MySql2Database): SqlBridge {
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
          .from(identitiesTable)
          .where(and(eq(identitiesTable.id, id), isNull(identitiesTable.deletedAt)))
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
          sql`select * from ${identitiesTable}
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
          sql`select * from ${identitiesTable}
              where JSON_CONTAINS(providers, ${needle})
                and deleted_at is null
                and (tenant_id is null or ${tenantId ?? null} is null or tenant_id = ${tenantId ?? null})
              limit 1`,
        )
        return (rows[0] as never) ?? null
      },
      insert: async (row) => {
        await db.insert(identitiesTable).values(row)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const r = await db
          .update(identitiesTable)
          .set(patch as never)
          .where(
            and(
              eq(identitiesTable.id, id),
              eq(identitiesTable.version, expectedVersion),
              tenantWhere(identitiesTable, tenantId),
            ),
          )
        // mysql2 returns `{ rowsAffected }`; fall back to reselect on success.
        if ((r as { rowsAffected?: number }).rowsAffected === 0) return null
        return reselect(identitiesTable, id)
      },
      softDelete: async (id, deletedAt, tenantId) => {
        await db
          .update(identitiesTable)
          .set({ deletedAt })
          .where(and(eq(identitiesTable.id, id), tenantWhere(identitiesTable, tenantId)))
      },
      restore: async (id, tenantId) => {
        await db
          .update(identitiesTable)
          .set({ deletedAt: null })
          .where(and(eq(identitiesTable.id, id), tenantWhere(identitiesTable, tenantId)))
        return reselect(identitiesTable, id)
      },
      erase: async (id, tenantId) => {
        await db.delete(credentialsTable).where(eq(credentialsTable.identityId, id))
        await db.delete(sessionsTable).where(eq(sessionsTable.identityId, id))
        await db.delete(identitiesTable).where(and(eq(identitiesTable.id, id), tenantWhere(identitiesTable, tenantId)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt, tenantId) => {
        // Portable across MySQL 5.7/8.x; wrap in `SELECT ... FOR UPDATE` if races.
        const rows = await db
          .select()
          .from(identitiesTable)
          .where(and(eq(identitiesTable.id, identityId), tenantWhere(identitiesTable, tenantId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        // parseProviderLinks fail-safes
        // malformed providers JSON to [] (was: crash on `null` /
        // non-array / `JSON.parse` SyntaxError).
        const arr = parseProviderLinks(cur.providers)
        const exists = arr.some(
          (p) => p.providerId === providerId && (providerSub === undefined || p.providerSub === providerSub),
        )
        if (exists) return
        arr.push(providerSub === undefined ? { providerId, addedAt } : { providerId, providerSub, addedAt })
        await db
          .update(identitiesTable)
          .set({ providers: JSON.stringify(arr) })
          .where(and(eq(identitiesTable.id, identityId), tenantWhere(identitiesTable, tenantId)))
      },
      deleteProviderLink: async (identityId, providerId, tenantId) => {
        const rows = await db
          .select()
          .from(identitiesTable)
          .where(and(eq(identitiesTable.id, identityId), tenantWhere(identitiesTable, tenantId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        // see insertProviderLink comment.
        const arr = parseProviderLinks(cur.providers)
        const next = arr.filter((p) => p.providerId !== providerId)
        await db
          .update(identitiesTable)
          .set({ providers: JSON.stringify(next) })
          .where(and(eq(identitiesTable.id, identityId), tenantWhere(identitiesTable, tenantId)))
      },
      merge: async (survivorId, dupId, tenantId) => {
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
        // Use `!== undefined` so empty-string tenant ids are honored
        // (truthy `tenantId ?` would drop the filter for '' and leak
        // across tenants).
        const where = [
          eq(credentialsTable.identityId, identityId),
          ...(kind !== undefined ? [eq(credentialsTable.kind, kind)] : []),
          ...(tenantId !== undefined ? [eq(credentialsTable.tenantId, tenantId)] : []),
        ]
        return db
          .select()
          .from(credentialsTable)
          .where(and(...where))
      },
      findByProviderSub: async (provider, sub, _tenantId) => {
        const rows = await db.execute(
          sql`select * from ${credentialsTable}
              where JSON_EXTRACT(metadata, '$.provider') = ${provider}
                and JSON_EXTRACT(metadata, '$.sub') = ${sub}
              limit 1`,
        )
        return (rows[0] as never) ?? null
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
        const r = await db
          .update(credentialsTable)
          .set(patch as never)
          .where(
            and(
              eq(credentialsTable.id, id),
              eq(credentialsTable.version, expectedVersion),
              tenantWhere(credentialsTable, tenantId),
            ),
          )
        if ((r as { rowsAffected?: number }).rowsAffected === 0) return null
        return reselect(credentialsTable, id)
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
        const r = await db
          .update(sessionsTable)
          .set(patch as never)
          .where(eq(sessionsTable.id, id))
        if ((r as { rowsAffected?: number }).rowsAffected === 0) return null
        return reselect(sessionsTable, id)
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
        const r = await db.delete(sessionsTable).where(lt(sessionsTable.absoluteExpiresAt, now))
        return (r as { rowsAffected?: number }).rowsAffected ?? 0
      },
    },
  }
}

// ---------------------------------------------------------------------
// Wire-up (replace with your own AuthRoot config)
// ---------------------------------------------------------------------
//
// import { drizzle } from 'drizzle-orm/mysql2'
// import mysql from 'mysql2/promise'
// import { createSqlAuthStores } from '../../sql'
//
// const pool = mysql.createPool({ uri: process.env.DATABASE_URL! })
// const db = drizzle(pool, { schema: { identitiesTable, credentialsTable, sessionsTable }, mode: 'default' })
// const bridge = createDrizzleMysqlAuthBridge(db)
// const stores = createSqlAuthStores<MyProfile>(bridge)
//
// new AuthRoot({ stores, ... })

/**
 * Storage helper that folds `mysql2 pool -> drizzle -> bridge -> stores`
 * into a single call. Returns `{ identities, sessions, credentials }`
 * for {@link defineAuth}.
 *
 * Accepts a connection-string, a pre-built `mysql2` pool, or a
 * pre-constructed `MySql2Database`.
 *
 * @example
 * ```ts
 * import { drizzleMysqlStorage } from '@gentleduck/auth/adapters/drizzle/mysql'
 *
 * defineAuth({ storage: drizzleMysqlStorage(process.env.DATABASE_URL!), ... })
 * ```
 */
export const drizzleMysqlStorage = <Profile = unknown>(
  input: string | MySql2Database | { execute: () => unknown },
): ReturnType<typeof createSqlAuthStores<Profile>> => {
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
  return createSqlAuthStores<Profile>(createDrizzleMysqlAuthBridge(db))
}
