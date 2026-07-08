/**
 * Drizzle (node-postgres) implementation of the {@link SqlBridge} contract.
 *
 * Two entry points:
 * - {@link createDrizzlePgBridge} — wrap an existing `NodePgDatabase`.
 * - {@link drizzlePgStorage} — fold a connection string / `pg.Pool` / db into ready-to-use stores.
 *
 * Queries are tenant-scoped when a `tenantId` is passed; `undefined` skips the
 * filter and `NULL`-tenant rows are treated as global (reachable from any tenant).
 */

import { createRequire } from 'node:module'
import { and, eq, isNull, lt, or, sql } from 'drizzle-orm'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import type { PgColumn } from 'drizzle-orm/pg-core'
import { createSqlStores, pickFreshestCredential } from '~/adapters/sql'
import type { SqlBridge } from '~/adapters/sql/sql.types'
import { credentialsTable, identitiesTable, sessionsTable } from './pg.schema'
import type { Pg } from './pg.types'

/**
 * Build the low-level {@link SqlBridge.Me} over a Drizzle pg database.
 *
 * Prefer {@link drizzlePgStorage}, which wires this into full stores; reach for
 * this directly only when you already hold a configured `NodePgDatabase`.
 *
 * @template TSchema - Drizzle schema attached to the db instance.
 * @param db - The Drizzle pg database instance.
 * @returns The identity / credential / session bridge for gentleduck/auth.
 */
export function createDrizzlePgBridge<const TSchema extends Record<string, unknown>>(
  db: NodePgDatabase<TSchema>,
): SqlBridge.Me {
  /** Scope a where clause by tenantId; undefined tenant skips the filter. */
  function tenantWhere<T extends { tenantId: PgColumn }>(table: T, tenantId: string | undefined) {
    return tenantId === undefined ? undefined : eq(table.tenantId, tenantId)
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
              sql`${identitiesTable.profile}->>'email' = ${email}`,
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
        // `@>` jsonb containment; matchPattern is bound as a parameter, never interpolated.
        const matchPattern = JSON.stringify([{ providerId, providerSub: sub }])
        const rows = await db
          .select()
          .from(identitiesTable)
          .where(
            and(
              sql`${identitiesTable.providers} @> ${matchPattern}::jsonb`,
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
        // FK CASCADE handles credentials and sessions; explicit deletes are belt-and-suspenders.
        await db.delete(credentialsTable).where(eq(credentialsTable.identityId, id))
        await db.delete(sessionsTable).where(eq(sessionsTable.identityId, id))
        await db.delete(identitiesTable).where(and(eq(identitiesTable.id, id), tenantWhere(identitiesTable, tenantId)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt, tenantId) => {
        // Remove existing link for this providerId, then append the new one.
        const newLink = JSON.stringify([{ providerId, providerSub: providerSub ?? null, addedAt }])
        await db.execute(
          sql`update ${identitiesTable}
              set providers = (
                select coalesce(jsonb_agg(elem), '[]'::jsonb)
                from jsonb_array_elements(providers) elem
                where (elem->>'providerId') != ${providerId}
              ) || ${newLink}::jsonb
              where id = ${identityId}
                and (${tenantId ?? null}::text is null or tenant_id = ${tenantId ?? null}::text)`,
        )
      },
      deleteProviderLink: async (identityId, providerId, tenantId) => {
        await db.execute(
          sql`update ${identitiesTable}
              set providers = (
                select coalesce(jsonb_agg(elem), '[]'::jsonb)
                from jsonb_array_elements(providers) elem
                where (elem->>'providerId') != ${providerId}
              )
              where id = ${identityId}
                and (${tenantId ?? null}::text is null or tenant_id = ${tenantId ?? null}::text)`,
        )
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
              sql`${credentialsTable.metadata}->>'provider' = ${provider}`,
              sql`${credentialsTable.metadata}->>'sub' = ${sub}`,
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
 * `pg` and `drizzle-orm` are optional peerDeps, lazily required only when a
 * connection string or `pg.Pool` is passed — supplying a `NodePgDatabase`
 * skips the require entirely.
 *
 * @template Profile - Identity profile shape.
 * @param input - A connection string, `pg.Pool`, or `NodePgDatabase`.
 * @returns The identity / credential / session stores for gentleduck/auth.
 */
export function drizzlePgStorage<Profile extends SqlBridge.ProfileMetadataBase>(
  input: string | Pg.NodePgPoolLike | Pg.AnyNodePgDatabase,
): ReturnType<typeof createSqlStores<Profile>> {
  function isNodePgDatabase(input: Pg.NodePgPoolLike | Pg.AnyNodePgDatabase): input is Pg.AnyNodePgDatabase {
    return typeof (input as Pg.AnyNodePgDatabase).select === 'function'
  }

  const lazyRequire = createRequire(import.meta.url)

  // Lazy-require to avoid a hard runtime dep when consumers wire the
  // bridge themselves; `pg` + `drizzle-orm` are optional peerDeps.
  let db: Pg.AnyNodePgDatabase
  if (typeof input === 'string') {
    const { Pool } = lazyRequire('pg')
    const { drizzle } = lazyRequire('drizzle-orm/node-postgres')
    db = drizzle(new Pool({ connectionString: input }))
  } else {
    if (isNodePgDatabase(input)) {
      db = input
    } else {
      const { drizzle } = lazyRequire('drizzle-orm/node-postgres')
      db = drizzle(input)
    }
  }
  // The bridge speaks the base profile shape; the caller asserts the concrete
  // `Profile` here (the DB `chk_auth_identities_profile_shape` check guarantees
  // the base keys exist at runtime). Single assertion, localized to this seam.
  return createSqlStores<Profile>(createDrizzlePgBridge(db) as SqlBridge.Me<Profile>)
}
