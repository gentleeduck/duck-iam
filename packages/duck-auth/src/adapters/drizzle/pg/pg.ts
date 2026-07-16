import { createRequire } from 'node:module'
import { and, eq, isNull, lt, sql } from 'drizzle-orm'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import type { PgColumn } from 'drizzle-orm/pg-core'
import { createSqlStores, pickFreshestCredential } from '~/adapters/sql'
import type { SqlBridge } from '~/adapters/sql/sql.types'
import { credentialsTable, identitiesTable, sessionsTable } from './pg.schema'
import type { Pg } from './pg.types'

/**
 * Postgres returns `jsonb` columns as already-parsed JSON, so the `Date`
 * fields nested inside `factors` and `actingAs` come back as ISO strings.
 * The Redis adapter revives these via `parseStoredDate`; mirror that here so
 * a materialized `Sessions.Me` satisfies its `Date`-typed contract (otherwise
 * strict response validators reject it). Top-level timestamptz columns are
 * already `Date` via drizzle's date mode and are left untouched.
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
          return { ...a, startedAt: new Date(a.startedAt as string), expiresAt: new Date(a.expiresAt as string) }
        })()
      : acting
  return { ...row, factors, actingAs }
}

export function createDrizzlePgBridge<const TSchema extends Record<string, unknown>>(
  db: NodePgDatabase<TSchema>,
): SqlBridge.Me {
  const tenantWhere = <T extends { tenantId: PgColumn }>(table: T, tenantId: string | undefined) =>
    tenantId === undefined ? undefined : eq(table.tenantId, tenantId)

  return {
    identities: {
      findById: (id) =>
        db
          .select()
          .from(identitiesTable)
          .where(and(eq(identitiesTable.id, id), isNull(identitiesTable.deletedAt)))
          .limit(1)
          .then((r) => r[0] ?? null),

      findByEmail: (email) =>
        db
          .select()
          .from(identitiesTable)
          .where(and(sql`${identitiesTable.profile}->>'email' = ${email}`, isNull(identitiesTable.deletedAt)))
          .limit(1)
          .then((r) => r[0] ?? null),

      findByProviderSub: (providerId, sub) =>
        db
          .select()
          .from(identitiesTable)
          .where(
            and(
              sql`${identitiesTable.providers} @> ${JSON.stringify([{ providerId, providerSub: sub }])}]::jsonb`,
              isNull(identitiesTable.deletedAt),
            ),
          )
          .limit(1)
          .then((r) => r[0] ?? null),

      insert: (row) =>
        db
          .insert(identitiesTable)
          .values(row)
          .then(() => {}),

      updateConditional: (id, patch, expectedVersion) =>
        db
          .update(identitiesTable)
          .set(patch)
          .where(and(eq(identitiesTable.id, id), eq(identitiesTable.version, expectedVersion)))
          .returning()
          .then((r) => r[0] ?? null),

      softDelete: (id, deletedAt) =>
        db
          .update(identitiesTable)
          .set({ deletedAt })
          .where(eq(identitiesTable.id, id))
          .then(() => {}),

      restore: (id) =>
        db
          .update(identitiesTable)
          .set({ deletedAt: null })
          .where(eq(identitiesTable.id, id))
          .returning()
          .then((r) => r[0] ?? null),

      erase: async (id) => {
        await db.delete(credentialsTable).where(eq(credentialsTable.identityId, id))
        await db.delete(sessionsTable).where(eq(sessionsTable.identityId, id))
        await db.delete(identitiesTable).where(eq(identitiesTable.id, id))
      },

      insertProviderLink: (identityId, providerId, providerSub, addedAt) =>
        db
          .execute(sql`
          update ${identitiesTable}
          set providers = (
            select coalesce(jsonb_agg(elem), '[]'::jsonb)
            from jsonb_array_elements(providers) elem
            where (elem->>'providerId') != ${providerId}
          ) || ${JSON.stringify([{ providerId, providerSub: providerSub ?? null, addedAt }])}]::jsonb
          where id = ${identityId}
        `)
          .then(() => {}),

      deleteProviderLink: (identityId, providerId) =>
        db
          .execute(sql`
          update ${identitiesTable}
          set providers = (
            select coalesce(jsonb_agg(elem), '[]'::jsonb)
            from jsonb_array_elements(providers) elem
            where (elem->>'providerId') != ${providerId}
          )
          where id = ${identityId}
        `)
          .then(() => {}),

      merge: async (survivorId, dupId) => {
        const [surv] = await db
          .select({ p: identitiesTable.providers })
          .from(identitiesTable)
          .where(eq(identitiesTable.id, survivorId))
          .limit(1)
        const [dupRow] = await db
          .select({ p: identitiesTable.providers })
          .from(identitiesTable)
          .where(eq(identitiesTable.id, dupId))
          .limit(1)
        if (surv && dupRow) {
          await db
            .update(identitiesTable)
            .set({ providers: [...(surv.p ?? []), ...(dupRow.p ?? [])] })
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

    credentials: {
      findById: (id, tenantId) =>
        db
          .select()
          .from(credentialsTable)
          .where(and(eq(credentialsTable.id, id), tenantWhere(credentialsTable, tenantId)))
          .limit(1)
          .then((r) => r[0] ?? null),

      listByIdentity: (identityId, kind, tenantId) =>
        db
          .select()
          .from(credentialsTable)
          .where(
            and(
              eq(credentialsTable.identityId, identityId),
              ...(kind ? [eq(credentialsTable.kind, kind)] : []),
              ...(tenantId ? [eq(credentialsTable.tenantId, tenantId)] : []),
            ),
          ),

      findByProviderSub: (provider, sub) =>
        db
          .select()
          .from(credentialsTable)
          .where(
            and(
              sql`${credentialsTable.metadata}->>'provider' = ${provider}`,
              sql`${credentialsTable.metadata}->>'sub' = ${sub}`,
            ),
          )
          .limit(1)
          .then((r) => r[0] ?? null),

      findByHashedSecret: (secretHash, kind, tenantId) =>
        db
          .select()
          .from(credentialsTable)
          .where(
            and(
              eq(credentialsTable.secret, secretHash),
              eq(credentialsTable.kind, kind),
              tenantWhere(credentialsTable, tenantId),
            ),
          )
          .then(pickFreshestCredential),

      insert: (row) =>
        db
          .insert(credentialsTable)
          .values(row)
          .then(() => {}),

      updateConditional: (id, patch, expectedVersion, tenantId) =>
        db
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
          .then((r) => r[0] ?? null),

      revoke: (id, revokedAt, tenantId) =>
        db
          .update(credentialsTable)
          .set({ revokedAt })
          .where(and(eq(credentialsTable.id, id), tenantWhere(credentialsTable, tenantId)))
          .then(() => {}),

      delete: (id, tenantId) =>
        db
          .delete(credentialsTable)
          .where(and(eq(credentialsTable.id, id), tenantWhere(credentialsTable, tenantId)))
          .then(() => {}),

      deleteByKind: (identityId, kind, tenantId) =>
        db
          .delete(credentialsTable)
          .where(
            and(
              eq(credentialsTable.identityId, identityId),
              eq(credentialsTable.kind, kind),
              tenantWhere(credentialsTable, tenantId),
            ),
          )
          .then(() => {}),
    },

    sessions: {
      insert: (row) =>
        db
          .insert(sessionsTable)
          .values(row)
          .then(() => {}),
      findByHash: (sidHash) =>
        db
          .select()
          .from(sessionsTable)
          .where(eq(sessionsTable.id, sidHash))
          .limit(1)
          .then((r) => reviveSessionRow(r[0] ?? null)),
      update: (id, patch) =>
        db
          .update(sessionsTable)
          .set(patch)
          .where(eq(sessionsTable.id, id))
          .returning()
          .then((r) => reviveSessionRow(r[0] ?? null)),
      delete: (id) =>
        db
          .delete(sessionsTable)
          .where(eq(sessionsTable.id, id))
          .then(() => {}),
      listByIdentity: (identityId) =>
        db
          .select()
          .from(sessionsTable)
          .where(eq(sessionsTable.identityId, identityId))
          .then((rows) => rows.map((r) => reviveSessionRowRequired(r))),
      deleteAllForIdentity: (identityId) =>
        db
          .delete(sessionsTable)
          .where(eq(sessionsTable.identityId, identityId))
          .then(() => {}),
      deleteExpired: (now) =>
        db
          .delete(sessionsTable)
          .where(lt(sessionsTable.absoluteExpiresAt, now))
          .returning()
          .then((r) => r.length),
    },
  }
}

export function drizzlePgStorage<Profile extends SqlBridge.ProfileMetadataBase>(
  input: string | Pg.NodePgPoolLike | Pg.AnyNodePgDatabase,
): ReturnType<typeof createSqlStores<Profile>> {
  const lazyRequire = createRequire(import.meta.url)
  const db =
    typeof input === 'string'
      ? lazyRequire('drizzle-orm/node-postgres').drizzle(new (lazyRequire('pg').Pool)({ connectionString: input }))
      : 'select' in input
        ? (input as Pg.AnyNodePgDatabase)
        : lazyRequire('drizzle-orm/node-postgres').drizzle(input)

  return createSqlStores<Profile>(createDrizzlePgBridge(db) as SqlBridge.Me<Profile>)
}
