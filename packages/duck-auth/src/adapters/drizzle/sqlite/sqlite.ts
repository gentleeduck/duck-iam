/**
 * Drizzle (SQLite) implementation of the {@link SqlBridge} contract.
 *
 * Two entry points:
 * - {@link createDrizzleSqliteBridge} — wrap an existing Drizzle sqlite db.
 * - {@link drizzleSqliteStorage} — fold a file path / better-sqlite3 client / db into ready-to-use stores.
 *
 * Driver-agnostic: works with better-sqlite3, libsql/Turso, or bun:sqlite.
 * SQLite has no jsonb containment operator, so provider-link lookups use
 * `json_each` and link edits are done read-modify-write at the bridge boundary.
 * Queries are tenant-scoped when a `tenantId` is passed; `undefined` skips the
 * filter and `NULL`-tenant rows are treated as global (reachable from any tenant).
 */

import { createRequire } from 'node:module'
import { and, eq, isNull, lt, sql } from 'drizzle-orm'
import type { BaseSQLiteDatabase, SQLiteColumn } from 'drizzle-orm/sqlite-core'
import { createSqlStores, pickFreshestCredential } from '~/adapters/sql'
import type { SqlBridge } from '~/adapters/sql/sql.types'
import { credentialsTable, identitiesTable, sessionsTable } from './sqlite.schema'
import type { Sqlite } from './sqlite.types'

/**
 * Build the low-level {@link SqlBridge.Me} over a Drizzle sqlite database.
 *
 * Prefer {@link drizzleSqliteStorage}, which wires this into full stores; reach
 * for this directly only when you already hold a configured sqlite db.
 *
 * @template TSchema - Drizzle schema attached to the db instance.
 * @param db - The Drizzle sqlite database instance.
 * @returns The identity / credential / session bridge for gentleduck/auth.
 */
export function createDrizzleSqliteBridge<const TSchema extends Record<string, unknown>>(
  db: BaseSQLiteDatabase<'sync' | 'async', unknown, TSchema>,
): SqlBridge.Me {
  /** Scope a where clause by tenantId; undefined tenant skips the filter. */
  function tenantWhere<T extends { tenantId: SQLiteColumn }>(table: T, tenantId: string | undefined) {
    return tenantId === undefined ? undefined : eq(table.tenantId, tenantId)
  }

  return {
    // --- Identities ---
    identities: {
      findById: async (id) => {
        const rows = await db
          .select()
          .from(identitiesTable)
          .where(and(eq(identitiesTable.id, id), isNull(identitiesTable.deletedAt)))
          .limit(1)
        const row = rows[0]
        if (!row) return null
        return row
      },
      findByEmail: async (email) => {
        const rows = await db
          .select()
          .from(identitiesTable)
          .where(
            and(sql`json_extract(${identitiesTable.profile}, '$.email') = ${email}`, isNull(identitiesTable.deletedAt)),
          )
          .limit(1)
        return rows[0] ?? null
      },
      findByProviderSub: async (providerId, sub) => {
        // No jsonb containment in SQLite; walk the providers array with json_each.
        const rows = await db
          .select()
          .from(identitiesTable)
          .where(
            and(
              sql`exists (
                select 1 from json_each(${identitiesTable.providers}) je
                where json_extract(je.value, '$.providerId') = ${providerId}
                  and json_extract(je.value, '$.providerSub') = ${sub}
              )`,
              isNull(identitiesTable.deletedAt),
            ),
          )
          .limit(1)
        return rows[0] ?? null
      },
      insert: async (row) => {
        await db.insert(identitiesTable).values(row)
      },
      updateConditional: async (id, patch, expectedVersion) => {
        const result = await db
          .update(identitiesTable)
          .set(patch)
          .where(and(eq(identitiesTable.id, id), eq(identitiesTable.version, expectedVersion)))
          .returning()
        return result[0] ?? null
      },
      softDelete: async (id, deletedAt) => {
        await db
          .update(identitiesTable)
          .set({ deletedAt })
          .where(and(eq(identitiesTable.id, id)))
      },
      restore: async (id) => {
        const result = await db
          .update(identitiesTable)
          .set({ deletedAt: null })
          .where(and(eq(identitiesTable.id, id)))
          .returning()
        return result[0] ?? null
      },
      erase: async (id) => {
        // FK CASCADE handles credentials and sessions; explicit deletes are belt-and-suspenders.
        await db.delete(credentialsTable).where(eq(credentialsTable.identityId, id))
        await db.delete(sessionsTable).where(eq(sessionsTable.identityId, id))
        await db.delete(identitiesTable).where(and(eq(identitiesTable.id, id)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt) => {
        // Read-modify-write: SQLite JSON edit functions are awkward; splice client-side.
        const rows = await db
          .select({ providers: identitiesTable.providers })
          .from(identitiesTable)
          .where(and(eq(identitiesTable.id, identityId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        const providers = cur.providers ?? []
        if (providers.some((p) => p.providerId === providerId && p.providerSub === providerSub)) return
        providers.push({ providerId, providerSub: providerSub ?? null, addedAt })
        await db
          .update(identitiesTable)
          .set({ providers })
          .where(and(eq(identitiesTable.id, identityId)))
      },
      deleteProviderLink: async (identityId, providerId) => {
        const rows = await db
          .select({ providers: identitiesTable.providers })
          .from(identitiesTable)
          .where(and(eq(identitiesTable.id, identityId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        const providers = (cur.providers ?? []).filter((p) => p.providerId !== providerId)
        await db
          .update(identitiesTable)
          .set({ providers })
          .where(and(eq(identitiesTable.id, identityId)))
      },
      merge: async (survivorId, dupId) => {
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
        // Global-account merge: repoint ALL of the dup's tenant-scoped rows
        // (across every tenant) before erasing it, so the FK cascade on delete
        // cannot orphan another tenant's credentials/sessions.
        await db.update(credentialsTable).set({ identityId: survivorId }).where(eq(credentialsTable.identityId, dupId))
        await db.update(sessionsTable).set({ identityId: survivorId }).where(eq(sessionsTable.identityId, dupId))
        await db.delete(identitiesTable).where(eq(identitiesTable.id, dupId))
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
              sql`json_extract(${credentialsTable.metadata}, '$.provider') = ${provider}`,
              sql`json_extract(${credentialsTable.metadata}, '$.sub') = ${sub}`,
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
        const result = await db.update(sessionsTable).set(patch).where(eq(sessionsTable.id, id)).returning()
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
 * One-call storage helper: folds `connection -> drizzle -> bridge -> stores`.
 *
 * `better-sqlite3` and `drizzle-orm` are optional peerDeps, lazily required
 * only when a file path or better-sqlite3 client is passed — supplying an
 * existing Drizzle sqlite db skips the require entirely.
 *
 * @template Profile - Identity profile shape.
 * @param input - A file path, better-sqlite3 `Database`, or Drizzle sqlite db.
 * @returns The identity / credential / session stores for gentleduck/auth.
 */
export function drizzleSqliteStorage<Profile extends SqlBridge.ProfileMetadataBase>(
  input: string | Sqlite.SqliteClientLike | Sqlite.AnySqliteDatabase,
): ReturnType<typeof createSqlStores<Profile>> {
  function isSqliteDatabase(
    value: Sqlite.SqliteClientLike | Sqlite.AnySqliteDatabase,
  ): value is Sqlite.AnySqliteDatabase {
    return typeof (value as Sqlite.AnySqliteDatabase).select === 'function'
  }

  const lazyRequire = createRequire(import.meta.url)

  let db: Sqlite.AnySqliteDatabase
  if (typeof input === 'string') {
    const Database = lazyRequire('better-sqlite3')
    const { drizzle } = lazyRequire('drizzle-orm/better-sqlite3')
    db = drizzle(new Database(input))
  } else if (isSqliteDatabase(input)) {
    db = input
  } else {
    const { drizzle } = lazyRequire('drizzle-orm/better-sqlite3')
    db = drizzle(input)
  }
  // The bridge is typed to the base profile; the caller asserts the concrete
  // `Profile` shape here (DB check constraints guarantee the base keys exist).
  return createSqlStores<Profile>(createDrizzleSqliteBridge(db) as unknown as SqlBridge.Me<Profile>)
}
