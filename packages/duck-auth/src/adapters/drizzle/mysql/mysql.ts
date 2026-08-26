/**
 * Drizzle (MySQL / MariaDB) implementation of the {@link SqlBridge} contract. MySQL has
 * no `RETURNING`, so mutations that must return the new row re-`SELECT` it, and JSON
 * lookups use `->>'$.key'`/`JSON_CONTAINS` instead of pg's `->>`/`@>`. Queries are
 * tenant-scoped when `tenantId` is passed; `undefined` skips the filter.
 */

import { createRequire } from 'node:module'
import { and, eq, isNull, lt, sql } from 'drizzle-orm'
import type { MySqlColumn } from 'drizzle-orm/mysql-core'
import type { MySql2Database } from 'drizzle-orm/mysql2'
import { createSqlStores, pickFreshestCredential } from '~/adapters/sql'
import type { SqlBridge } from '~/adapters/sql/sql.types'
import type { Identities } from '~/core/identities'
import { authCredentials, authIdentities, authSessions } from './mysql.schema'
import type { Mysql } from './mysql.types'

/**
 * MySQL returns `json` columns as already-parsed JSON, so `Date` fields nested inside
 * `factors`/`actingAs` arrive as ISO strings while `Sessions.Me` types them as `Date`.
 * Revive them here, same as the pg adapter and the Redis store's `parseStoredDate`.
 */
function reviveSessionRow<T extends { factors: unknown; actingAs: unknown }>(row: T | null): T | null {
  return row ? reviveSessionRowRequired(row) : null
}

function reviveSessionRowRequired<T extends { factors: unknown; actingAs: unknown }>(row: T): T {
  const factors = Array.isArray(row.factors)
    ? row.factors.map((f) => {
        const factor = f as { completedAt: unknown }
        return { ...factor, completedAt: new Date(factor.completedAt as string) }
      })
    : row.factors
  const acting = row.actingAs
  const actingAs =
    acting && typeof acting === 'object'
      ? (() => {
          const a = acting as { startedAt: unknown; expiresAt: unknown }
          return { ...a, expiresAt: new Date(a.expiresAt as string), startedAt: new Date(a.startedAt as string) }
        })()
      : acting
  return { ...row, actingAs, factors }
}

/** Generic over the profile so callers with their own profile shape don't have to cast. */
export function createDrizzleMysqlBridge<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  const TSchema extends Record<string, unknown> = Record<string, unknown>,
>(db: MySql2Database<TSchema>): SqlBridge.Me<Profile> {
  /** Scope a where clause by tenantId; undefined tenant skips the filter. */
  function tenantWhere<T extends { tenantId: MySqlColumn }>(table: T, tenantId: string | undefined) {
    return tenantId === undefined ? undefined : eq(table.tenantId, tenantId)
  }

  /** MySQL has no RETURNING, so re-select a row by primary key after a mutation. */
  async function reselectIdentity(id: string) {
    const rows = await db.select().from(authIdentities).where(eq(authIdentities.id, id)).limit(1)
    return rows[0] ?? null
  }
  async function reselectCredential(id: string) {
    const rows = await db.select().from(authCredentials).where(eq(authCredentials.id, id)).limit(1)
    return rows[0] ?? null
  }
  async function reselectSession(id: string) {
    const rows = await db.select().from(authSessions).where(eq(authSessions.id, id)).limit(1)
    return reviveSessionRow(rows[0] ?? null)
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
            and(sql`lower(${authIdentities.profile}->>'$.email') = lower(${email})`, isNull(authIdentities.deletedAt)),
          )
          .limit(1)
        return rows[0] ?? null
      },
      findByProviderSub: async (providerId, sub) => {
        // JSON_CONTAINS(target, candidate); needle is bound as a parameter, never interpolated.
        const needle = JSON.stringify({ providerId, providerSub: sub })
        const rows = await db
          .select()
          .from(authIdentities)
          .where(and(sql`json_contains(${authIdentities.providers}, ${needle})`, isNull(authIdentities.deletedAt)))
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
        if (result[0].affectedRows === 0) return null
        return reselectIdentity(id)
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
        if (result[0].affectedRows === 0) return null
        return reselectIdentity(id)
      },
      erase: async (id) => {
        // FK CASCADE handles credentials and sessions; explicit deletes are belt-and-suspenders.
        await db.delete(authCredentials).where(eq(authCredentials.identityId, id))
        await db.delete(authSessions).where(eq(authSessions.identityId, id))
        await db.delete(authIdentities).where(and(eq(authIdentities.id, id)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt) => {
        // Read-modify-write: portable across MySQL 5.7/8.x/MariaDB; splice client-side.
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
              sql`${authCredentials.metadata}->>'$.provider' = ${provider}`,
              sql`${authCredentials.metadata}->>'$.sub' = ${sub}`,
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
        if (result[0].affectedRows === 0) return null
        return reselectCredential(id)
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
        return reviveSessionRow(rows[0] ?? null)
      },
      update: async (id, patch) => {
        const result = await db.update(authSessions).set(patch).where(eq(authSessions.id, id))
        if (result[0].affectedRows === 0) return null
        return reselectSession(id)
      },
      delete: async (id) => {
        await db.delete(authSessions).where(eq(authSessions.id, id))
      },
      listByIdentity: async (identityId) => {
        const rows = await db.select().from(authSessions).where(eq(authSessions.identityId, identityId))
        return rows.map(reviveSessionRowRequired)
      },
      deleteAllForIdentity: async (identityId) => {
        await db.delete(authSessions).where(eq(authSessions.identityId, identityId))
      },
      deleteExpired: async (now) => {
        const result = await db.delete(authSessions).where(lt(authSessions.absoluteExpiresAt, now))
        return result[0].affectedRows
      },
    },
  }

  // One assertion here instead of one at every call site: drizzle types `profile` as
  // the base shape, and `Profile` is the caller's refinement of it.
  return bridge as SqlBridge.Me<Profile>
}

/**
 * One-call storage helper: folds `connection -> drizzle -> bridge -> stores`. `mysql2`
 * and `drizzle-orm` are optional peerDeps, lazily required only when a connection
 * string or mysql2 pool is passed; a `MySql2Database` skips the require entirely.
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
  // Asserts the concrete `Profile` shape; DB check constraints guarantee the base keys exist.
  return createSqlStores<Profile>(createDrizzleMysqlBridge(db) as unknown as SqlBridge.Me<Profile>)
}
