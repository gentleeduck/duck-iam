/**
 * Drizzle (MySQL / MariaDB) implementation of the {@link SqlBridge} contract.
 *
 * Two entry points:
 * - {@link createDrizzleMysqlBridge} — wrap an existing `MySql2Database`.
 * - {@link drizzleMysqlStorage} — fold a connection string / mysql2 pool / db into ready-to-use stores.
 *
 * Differences from the pg flavour:
 * - MySQL has no `RETURNING`; mutations that must return the new row re-`SELECT` it.
 * - JSON path lookups use `->>'$.key'` and `JSON_CONTAINS` instead of pg's `->>` / `@>`.
 * Queries are tenant-scoped when a `tenantId` is passed; `undefined` skips the
 * filter and `NULL`-tenant rows are treated as global (reachable from any tenant).
 */

import { createRequire } from 'node:module'
import { and, eq, isNull, lt, or, sql } from 'drizzle-orm'
import type { MySqlColumn } from 'drizzle-orm/mysql-core'
import type { MySql2Database } from 'drizzle-orm/mysql2'
import { createSqlStores, pickFreshestCredential } from '../../sql'
import type { SqlBridge } from '../../sql/sql.types'
import { credentialsTable, identitiesTable, sessionsTable } from './mysql.schema'
import type { Mysql } from './mysql.types'

/**
 * Build the low-level {@link SqlBridge.Me} over a Drizzle mysql database.
 *
 * Prefer {@link drizzleMysqlStorage}, which wires this into full stores; reach
 * for this directly only when you already hold a configured `MySql2Database`.
 *
 * @template TSchema - Drizzle schema attached to the db instance.
 * @param db - The Drizzle mysql database instance.
 * @returns The identity / credential / session bridge for gentleduck/auth.
 */
export function createDrizzleMysqlBridge<const TSchema extends Record<string, unknown>>(
  db: MySql2Database<TSchema>,
): SqlBridge.Me {
  /** Scope a where clause by tenantId; undefined tenant skips the filter. */
  function tenantWhere<T extends { tenantId: MySqlColumn }>(table: T, tenantId: string | undefined) {
    return tenantId === undefined ? undefined : eq(table.tenantId, tenantId)
  }

  /** MySQL has no RETURNING — re-select a row by primary key after a mutation. */
  async function reselectIdentity(id: string) {
    const rows = await db.select().from(identitiesTable).where(eq(identitiesTable.id, id)).limit(1)
    return rows[0] ?? null
  }
  async function reselectCredential(id: string) {
    const rows = await db.select().from(credentialsTable).where(eq(credentialsTable.id, id)).limit(1)
    return rows[0] ?? null
  }
  async function reselectSession(id: string) {
    const rows = await db.select().from(sessionsTable).where(eq(sessionsTable.id, id)).limit(1)
    return rows[0] ?? null
  }

  return {
    // --- Identities ---
    identities: {
      findById: async (id, tenantId) => {
        // Tenant is checked after the fetch so NULL-tenant (global) rows stay visible.
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
        const rows = await db
          .select()
          .from(identitiesTable)
          .where(
            and(
              sql`${identitiesTable.profile}->>'$.email' = ${email}`,
              isNull(identitiesTable.deletedAt),
              tenantId === undefined
                ? undefined
                : or(isNull(identitiesTable.tenantId), eq(identitiesTable.tenantId, tenantId)),
            ),
          )
          .limit(1)
        return rows[0] ?? null
      },
      findByProviderSub: async (providerId, sub, tenantId) => {
        // JSON_CONTAINS(target, candidate); needle is bound as a parameter, never interpolated.
        const needle = JSON.stringify({ providerId, providerSub: sub })
        const rows = await db
          .select()
          .from(identitiesTable)
          .where(
            and(
              sql`json_contains(${identitiesTable.providers}, ${needle})`,
              isNull(identitiesTable.deletedAt),
              tenantId === undefined
                ? undefined
                : or(isNull(identitiesTable.tenantId), eq(identitiesTable.tenantId, tenantId)),
            ),
          )
          .limit(1)
        return rows[0] ?? null
      },
      insert: async (row) => {
        await db.insert(identitiesTable).values(row)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const result = await db
          .update(identitiesTable)
          .set(patch)
          .where(
            and(
              eq(identitiesTable.id, id),
              eq(identitiesTable.version, expectedVersion),
              tenantWhere(identitiesTable, tenantId),
            ),
          )
        if (result[0].affectedRows === 0) return null
        return reselectIdentity(id)
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
        if (result[0].affectedRows === 0) return null
        return reselectIdentity(id)
      },
      erase: async (id, tenantId) => {
        // FK CASCADE handles credentials and sessions; explicit deletes are belt-and-suspenders.
        await db.delete(credentialsTable).where(eq(credentialsTable.identityId, id))
        await db.delete(sessionsTable).where(eq(sessionsTable.identityId, id))
        await db.delete(identitiesTable).where(and(eq(identitiesTable.id, id), tenantWhere(identitiesTable, tenantId)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt, tenantId) => {
        // Read-modify-write: portable across MySQL 5.7/8.x/MariaDB; splice client-side.
        const rows = await db
          .select({ providers: identitiesTable.providers })
          .from(identitiesTable)
          .where(and(eq(identitiesTable.id, identityId), tenantWhere(identitiesTable, tenantId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        const providers = cur.providers ?? []
        if (providers.some((p) => p.providerId === providerId && p.providerSub === providerSub)) return
        providers.push({ providerId, providerSub: providerSub ?? null, addedAt })
        await db
          .update(identitiesTable)
          .set({ providers })
          .where(and(eq(identitiesTable.id, identityId), tenantWhere(identitiesTable, tenantId)))
      },
      deleteProviderLink: async (identityId, providerId, tenantId) => {
        const rows = await db
          .select({ providers: identitiesTable.providers })
          .from(identitiesTable)
          .where(and(eq(identitiesTable.id, identityId), tenantWhere(identitiesTable, tenantId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        const providers = (cur.providers ?? []).filter((p) => p.providerId !== providerId)
        await db
          .update(identitiesTable)
          .set({ providers })
          .where(and(eq(identitiesTable.id, identityId), tenantWhere(identitiesTable, tenantId)))
      },
      merge: async (survivorId, dupId, tenantId) => {
        // Union dup's provider links into the survivor before re-pointing rows.
        const [surv] = await db
          .select({ providers: identitiesTable.providers })
          .from(identitiesTable)
          .where(eq(identitiesTable.id, survivorId))
          .limit(1)
        const [dupRow] = await db
          .select({ providers: identitiesTable.providers })
          .from(identitiesTable)
          .where(eq(identitiesTable.id, dupId))
          .limit(1)
        if (surv && dupRow) {
          await db
            .update(identitiesTable)
            .set({ providers: [...(surv.providers ?? []), ...(dupRow.providers ?? [])] })
            .where(eq(identitiesTable.id, survivorId))
        }
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
    // --- Credentials ---
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
        const rows = await db
          .select()
          .from(credentialsTable)
          .where(
            and(
              sql`${credentialsTable.metadata}->>'$.provider' = ${provider}`,
              sql`${credentialsTable.metadata}->>'$.sub' = ${sub}`,
            ),
          )
          .limit(1)
        return rows[0] ?? null
      },
      findByHashedSecret: async (secretHash, kind, tenantId) => {
        // Prefer the freshest live row; fall back to the freshest revoked one
        // so callers can distinguish "revoked" from "never existed".
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
        return pickFreshestCredential(rows)
      },
      insert: async (row) => {
        await db.insert(credentialsTable).values(row)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const result = await db
          .update(credentialsTable)
          .set(patch)
          .where(
            and(
              eq(credentialsTable.id, id),
              eq(credentialsTable.version, expectedVersion),
              tenantWhere(credentialsTable, tenantId),
            ),
          )
        if (result[0].affectedRows === 0) return null
        return reselectCredential(id)
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
    // --- Sessions ---
    sessions: {
      insert: async (row) => {
        await db.insert(sessionsTable).values(row)
      },
      findByHash: async (sidHash) => {
        const rows = await db.select().from(sessionsTable).where(eq(sessionsTable.id, sidHash)).limit(1)
        return rows[0] ?? null
      },
      update: async (id, patch) => {
        const result = await db.update(sessionsTable).set(patch).where(eq(sessionsTable.id, id))
        if (result[0].affectedRows === 0) return null
        return reselectSession(id)
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
        const result = await db.delete(sessionsTable).where(lt(sessionsTable.absoluteExpiresAt, now))
        return result[0].affectedRows
      },
    },
  }
}

/**
 * One-call storage helper: folds `connection -> drizzle -> bridge -> stores`.
 *
 * `mysql2` and `drizzle-orm` are optional peerDeps, lazily required only when a
 * connection string or mysql2 pool is passed — supplying a `MySql2Database`
 * skips the require entirely.
 *
 * @template Profile - Identity profile shape.
 * @param input - A connection string, mysql2 pool, or `MySql2Database`.
 * @returns The identity / credential / session stores for gentleduck/auth.
 */
export function drizzleMysqlStorage<Profile extends SqlBridge.ProfileMetadataBase>(
  input: string | Mysql.MySql2PoolLike | Mysql.AnyMySql2Database,
): ReturnType<typeof createSqlStores<Profile>> {
  function isMysqlDatabase(value: Mysql.MySql2PoolLike | Mysql.AnyMySql2Database): value is Mysql.AnyMySql2Database {
    return typeof (value as Mysql.AnyMySql2Database).select === 'function'
  }

  const lazyRequire = createRequire(import.meta.url)

  let db: Mysql.AnyMySql2Database
  if (typeof input === 'string') {
    const mysql = lazyRequire('mysql2/promise')
    const { drizzle } = lazyRequire('drizzle-orm/mysql2')
    db = drizzle(mysql.createPool(input))
  } else if (isMysqlDatabase(input)) {
    db = input
  } else {
    const { drizzle } = lazyRequire('drizzle-orm/mysql2')
    db = drizzle(input)
  }
  // The bridge is typed to the base profile; the caller asserts the concrete
  // `Profile` shape here (DB check constraints guarantee the base keys exist).
  return createSqlStores<Profile>(createDrizzleMysqlBridge(db) as unknown as SqlBridge.Me<Profile>)
}
