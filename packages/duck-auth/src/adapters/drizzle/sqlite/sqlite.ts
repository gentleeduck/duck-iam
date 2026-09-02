/**
 * Drizzle (SQLite) implementation of the {@link SqlBridge} contract. Driver-agnostic:
 * works with better-sqlite3, libsql/Turso, or bun:sqlite. SQLite has no jsonb
 * containment operator, so provider-link lookups use `json_each` and link edits are
 * read-modify-write at the bridge boundary. Queries are tenant-scoped when `tenantId`
 * is passed; `undefined` skips the filter.
 */

import { createRequire } from 'node:module'
import { and, eq, inArray, isNull, lt, sql } from 'drizzle-orm'
import type { BaseSQLiteDatabase, SQLiteColumn } from 'drizzle-orm/sqlite-core'
import { createSqlStores, pickFreshestCredential } from '~/adapters/sql'
import type { SqlBridge } from '~/adapters/sql/sql.types'
import type { Identities } from '~/core/identities'
import { authCredentials, authIdentities, authSessions } from './sqlite.schema'
import type { Sqlite } from './sqlite.types'

/** Generic over the profile so callers with their own profile shape don't have to cast. */
export function createDrizzleSqliteBridge<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  const TSchema extends Record<string, unknown> = Record<string, unknown>,
>(db: BaseSQLiteDatabase<'sync' | 'async', unknown, TSchema>): SqlBridge.Me<Profile> {
  /** Scope a where clause by tenantId; undefined tenant skips the filter. */
  function tenantWhere<T extends { tenantId: SQLiteColumn }>(table: T, tenantId: string | undefined) {
    return tenantId === undefined ? undefined : eq(table.tenantId, tenantId)
  }

  const bridge: SqlBridge.Me = {
    // --- Identities ---
    identities: {
      findById: async (id) => {
        const rows = await db
          .select()
          .from(authIdentities)
          .where(and(eq(authIdentities.id, id), isNull(authIdentities.deletedAt)))
          .limit(1)
        const row = rows[0]
        if (!row) return null
        return row
      },
      findByEmail: async (email) => {
        const rows = await db
          .select()
          .from(authIdentities)
          .where(
            and(
              sql`lower(json_extract(${authIdentities.profile}, '$.email')) = lower(${email})`,
              isNull(authIdentities.deletedAt),
            ),
          )
          .limit(1)
        return rows[0] ?? null
      },
      findByProviderSub: async (providerId, sub) => {
        // No jsonb containment in SQLite, so walk the providers array with json_each.
        const rows = await db
          .select()
          .from(authIdentities)
          .where(
            and(
              sql`exists (
                select 1 from json_each(${authIdentities.providers}) je
                where json_extract(je.value, '$.providerId') = ${providerId}
                  and json_extract(je.value, '$.providerSub') = ${sub}
              )`,
              isNull(authIdentities.deletedAt),
            ),
          )
          .limit(1)
        return rows[0] ?? null
      },
      insert: async (row) => {
        await db.insert(authIdentities).values(row)
      },
      updateConditional: async (id, patch, expectedVersion) => {
        const result = await db
          .update(authIdentities)
          .set(patch)
          .where(and(eq(authIdentities.id, id), eq(authIdentities.version, expectedVersion)))
          .returning()
        return result[0] ?? null
      },
      softDelete: async (id, deletedAt) => {
        await db
          .update(authIdentities)
          .set({ deletedAt })
          .where(and(eq(authIdentities.id, id)))
      },
      restore: async (id) => {
        const result = await db
          .update(authIdentities)
          .set({ deletedAt: null })
          .where(and(eq(authIdentities.id, id)))
          .returning()
        return result[0] ?? null
      },
      erase: async (id) => {
        // FK CASCADE handles credentials and sessions; explicit deletes are belt-and-suspenders.
        await db.delete(authCredentials).where(eq(authCredentials.identityId, id))
        await db.delete(authSessions).where(eq(authSessions.identityId, id))
        await db.delete(authIdentities).where(and(eq(authIdentities.id, id)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt) => {
        // Read-modify-write: SQLite JSON edit functions are awkward; splice client-side.
        const rows = await db
          .select({ providers: authIdentities.providers })
          .from(authIdentities)
          .where(and(eq(authIdentities.id, identityId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        const providers = cur.providers ?? []
        if (providers.some((p) => p.providerId === providerId && p.providerSub === providerSub)) return
        providers.push({ providerId, providerSub: providerSub ?? null, addedAt })
        await db
          .update(authIdentities)
          .set({ providers })
          .where(and(eq(authIdentities.id, identityId)))
      },
      deleteProviderLink: async (identityId, providerId) => {
        const rows = await db
          .select({ providers: authIdentities.providers })
          .from(authIdentities)
          .where(and(eq(authIdentities.id, identityId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        const providers = (cur.providers ?? []).filter((p) => p.providerId !== providerId)
        await db
          .update(authIdentities)
          .set({ providers })
          .where(and(eq(authIdentities.id, identityId)))
      },
      softDeleteManyReturningIds: async (ids, deletedAt) => {
        const rows = await db
          .update(authIdentities)
          .set({ deletedAt })
          .where(and(inArray(authIdentities.id, [...ids]), isNull(authIdentities.deletedAt)))
          .returning({ id: authIdentities.id })
        return rows.map((r) => r.id)
      },

      eraseManyReturningIds: async (ids) => {
        const list = [...ids]
        // FK CASCADE covers these; explicit deletes are belt-and-suspenders, as
        // in the single-row `erase` above.
        await db.delete(authCredentials).where(inArray(authCredentials.identityId, list))
        await db.delete(authSessions).where(inArray(authSessions.identityId, list))
        const gone = await db
          .delete(authIdentities)
          .where(inArray(authIdentities.id, list))
          .returning({ id: authIdentities.id })
        return gone.map((r) => r.id)
      },

      restoreManyReturning: (ids) =>
        db
          .update(authIdentities)
          .set({ deletedAt: null })
          .where(inArray(authIdentities.id, [...ids]))
          .returning(),

      /**
       * SQLite has no `UPDATE ... FROM (VALUES ...)`, so each row still needs
       * its own conditional update to be matched on its own expected version.
       * They run back-to-back on one connection - inside the caller's
       * transaction when there is one - so the batch is still atomic; it is the
       * statement count, not the atomicity, that SQLite cannot collapse.
       */
      updateProfileManyReturning: async (rows) => {
        const out: (typeof authIdentities.$inferSelect)[] = []
        for (const r of rows) {
          const updated = await db
            .update(authIdentities)
            .set(r.patch)
            .where(and(eq(authIdentities.id, r.id), eq(authIdentities.version, r.expectedVersion)))
            .returning()
          const row = updated[0]
          if (row) out.push(row)
        }
        return out
      },

      merge: async (survivorId, dupId) => {
        // Union dup's provider links into the survivor before re-pointing rows.
        const [surv] = await db
          .select({ providers: authIdentities.providers })
          .from(authIdentities)
          .where(eq(authIdentities.id, survivorId))
          .limit(1)
        const [dupRow] = await db
          .select({ providers: authIdentities.providers })
          .from(authIdentities)
          .where(eq(authIdentities.id, dupId))
          .limit(1)
        if (surv && dupRow) {
          await db
            .update(authIdentities)
            .set({ providers: [...(surv.providers ?? []), ...(dupRow.providers ?? [])] })
            .where(eq(authIdentities.id, survivorId))
        }
        // Repoint all of the dup's rows across every tenant before erasing it, so the
        // FK cascade on delete cannot orphan another tenant's credentials/sessions.
        await db.update(authCredentials).set({ identityId: survivorId }).where(eq(authCredentials.identityId, dupId))
        await db.update(authSessions).set({ identityId: survivorId }).where(eq(authSessions.identityId, dupId))
        await db.delete(authIdentities).where(eq(authIdentities.id, dupId))
      },
    },
    // --- Credentials ---
    credentials: {
      findById: async (id, tenantId) => {
        const rows = await db
          .select()
          .from(authCredentials)
          .where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
          .limit(1)
        return rows[0] ?? null
      },
      listByIdentity: async (identityId, kind, tenantId) => {
        const where = [
          eq(authCredentials.identityId, identityId),
          ...(kind ? [eq(authCredentials.kind, kind)] : []),
          ...(tenantId ? [eq(authCredentials.tenantId, tenantId)] : []),
        ]
        return db
          .select()
          .from(authCredentials)
          .where(and(...where))
      },
      findByProviderSub: async (provider, sub, _tenantId) => {
        const rows = await db
          .select()
          .from(authCredentials)
          .where(
            and(
              sql`json_extract(${authCredentials.metadata}, '$.provider') = ${provider}`,
              sql`json_extract(${authCredentials.metadata}, '$.sub') = ${sub}`,
            ),
          )
          .limit(1)
        return rows[0] ?? null
      },
      findByHashedSecret: async (secretHash, kind, tenantId) => {
        // Prefer the freshest live row, fall back to freshest revoked.
        const rows = await db
          .select()
          .from(authCredentials)
          .where(
            and(
              eq(authCredentials.secret, secretHash),
              eq(authCredentials.kind, kind),
              tenantWhere(authCredentials, tenantId),
            ),
          )
        return pickFreshestCredential(rows)
      },
      insert: async (row) => {
        await db.insert(authCredentials).values(row)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const result = await db
          .update(authCredentials)
          .set(patch)
          .where(
            and(
              eq(authCredentials.id, id),
              eq(authCredentials.version, expectedVersion),
              tenantWhere(authCredentials, tenantId),
            ),
          )
          .returning()
        return result[0] ?? null
      },
      revoke: async (id, revokedAt, tenantId) => {
        await db
          .update(authCredentials)
          .set({ revokedAt })
          .where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
      },
      delete: async (id, tenantId) => {
        await db.delete(authCredentials).where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
      },
      deleteByIdentitiesReturningIds: async (identityIds, tenantId) => {
        const rows = await db
          .delete(authCredentials)
          .where(and(inArray(authCredentials.identityId, [...identityIds]), tenantWhere(authCredentials, tenantId)))
          .returning({ id: authCredentials.identityId })
        return rows.map((r) => r.id).filter((id): id is string => id !== null)
      },
      deleteByKind: async (identityId, kind, tenantId) => {
        await db
          .delete(authCredentials)
          .where(
            and(
              eq(authCredentials.identityId, identityId),
              eq(authCredentials.kind, kind),
              tenantWhere(authCredentials, tenantId),
            ),
          )
      },
    },
    // --- Sessions ---
    sessions: {
      insert: async (row) => {
        await db.insert(authSessions).values(row)
      },
      findByHash: async (sidHash) => {
        const rows = await db.select().from(authSessions).where(eq(authSessions.id, sidHash)).limit(1)
        return rows[0] ?? null
      },
      update: async (id, patch) => {
        const result = await db.update(authSessions).set(patch).where(eq(authSessions.id, id)).returning()
        return result[0] ?? null
      },
      delete: async (id) => {
        await db.delete(authSessions).where(eq(authSessions.id, id))
      },
      listByIdentity: async (identityId) => {
        return db.select().from(authSessions).where(eq(authSessions.identityId, identityId))
      },
      deleteAllForIdentity: async (identityId) => {
        await db.delete(authSessions).where(eq(authSessions.identityId, identityId))
      },
      deleteAllForIdentitiesReturningIds: async (identityIds) => {
        const rows = await db
          .delete(authSessions)
          .where(inArray(authSessions.identityId, [...identityIds]))
          .returning({ id: authSessions.identityId })
        return rows.map((r) => r.id).filter((id): id is string => id !== null)
      },
      deleteManyReturningIds: async (ids) => {
        const rows = await db
          .delete(authSessions)
          .where(inArray(authSessions.id, [...ids]))
          .returning({ id: authSessions.id })
        return rows.map((r) => r.id)
      },
      listByIdentities: (identityIds) =>
        db
          .select()
          .from(authSessions)
          .where(inArray(authSessions.identityId, [...identityIds])),
      deleteExpired: async (now) => {
        const result = await db.delete(authSessions).where(lt(authSessions.absoluteExpiresAt, now)).returning()
        return result.length
      },
    },
    /**
     * Re-make this bridge against `client` - a drizzle transaction handle,
     * which is structurally the same database surface for every query builder
     * this bridge uses. The assertion is the boundary where an opaque client
     * re-enters the driver's own type, and belongs here rather than in `core/`
     * precisely because this file is the only one that knows the driver.
     */
    withClient: (client) =>
      createDrizzleSqliteBridge<Profile, TSchema>(client as BaseSQLiteDatabase<'sync' | 'async', unknown, TSchema>),
  }

  // One assertion here instead of one at every call site: drizzle types `profile` as
  // the base shape, and `Profile` is the caller's refinement of it.
  return bridge as SqlBridge.Me<Profile>
}

/**
 * One-call storage helper: folds `connection -> drizzle -> bridge -> stores`.
 * `better-sqlite3` and `drizzle-orm` are optional peerDeps, lazily required only when a
 * file path or better-sqlite3 client is passed; an existing Drizzle sqlite db skips
 * the require entirely.
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
  // Asserts the concrete `Profile` shape; DB check constraints guarantee the base keys exist.
  return createSqlStores<Profile>(createDrizzleSqliteBridge(db) as unknown as SqlBridge.Me<Profile>)
}
