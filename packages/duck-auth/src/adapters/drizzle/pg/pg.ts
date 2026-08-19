import { createRequire } from 'node:module'
import { and, eq, isNull, lt, sql } from 'drizzle-orm'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import type { PgColumn } from 'drizzle-orm/pg-core'
import { createSqlStores, pickFreshestCredential } from '~/adapters/sql'
import type { SqlBridge } from '~/adapters/sql/sql.types'
import type { Identities } from '~/core/identities'
import { authCredentials, authIdentities, authSessions } from './pg.schema'
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

/**
 * Generic over the profile so a caller with its own profile shape does not have to
 * cast the result. The row's `profile` column is typed as the base shape by drizzle,
 * so the widening happens once here rather than at every call site.
 */
export function createDrizzlePgBridge<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  const TSchema extends Record<string, unknown> = Record<string, unknown>,
>(db: NodePgDatabase<TSchema>): SqlBridge.Me<Profile> {
  const tenantWhere = <T extends { tenantId: PgColumn }>(table: T, tenantId: string | undefined) =>
    tenantId === undefined ? undefined : eq(table.tenantId, tenantId)

  const bridge: SqlBridge.Me = {
    identities: {
      findById: (id) =>
        db
          .select()
          .from(authIdentities)
          .where(and(eq(authIdentities.id, id), isNull(authIdentities.deletedAt)))
          .limit(1)
          .then((r) => r[0] ?? null),

      // Case-insensitive to match the uniqueness constraint, which is
      // `unique (lower(profile->>'email'))`. An exact match here meant an identity
      // registered as `Ada@x.com` could never sign in again: signup stores the
      // address verbatim, and the lookup never found it.
      findByEmail: (email) =>
        db
          .select()
          .from(authIdentities)
          .where(
            and(sql`lower(${authIdentities.profile}->>'email') = lower(${email})`, isNull(authIdentities.deletedAt)),
          )
          .limit(1)
          .then((r) => r[0] ?? null),

      findByProviderSub: (providerId, sub) =>
        db
          .select()
          .from(authIdentities)
          .where(
            and(
              sql`${authIdentities.providers} @> ${JSON.stringify([{ providerId, providerSub: sub }])}]::jsonb`,
              isNull(authIdentities.deletedAt),
            ),
          )
          .limit(1)
          .then((r) => r[0] ?? null),

      insert: (row) =>
        db
          .insert(authIdentities)
          .values(row)
          .then(() => {}),

      updateConditional: (id, patch, expectedVersion) =>
        db
          .update(authIdentities)
          .set(patch)
          .where(and(eq(authIdentities.id, id), eq(authIdentities.version, expectedVersion)))
          .returning()
          .then((r) => r[0] ?? null),

      softDelete: (id, deletedAt) =>
        db
          .update(authIdentities)
          .set({ deletedAt })
          .where(eq(authIdentities.id, id))
          .then(() => {}),

      restore: (id) =>
        db
          .update(authIdentities)
          .set({ deletedAt: null })
          .where(eq(authIdentities.id, id))
          .returning()
          .then((r) => r[0] ?? null),

      erase: async (id) => {
        await db.delete(authCredentials).where(eq(authCredentials.identityId, id))
        await db.delete(authSessions).where(eq(authSessions.identityId, id))
        await db.delete(authIdentities).where(eq(authIdentities.id, id))
      },

      insertProviderLink: (identityId, providerId, providerSub, addedAt) =>
        db
          .execute(sql`
          update ${authIdentities}
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
          update ${authIdentities}
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
          .select({ p: authIdentities.providers })
          .from(authIdentities)
          .where(eq(authIdentities.id, survivorId))
          .limit(1)
        const [dupRow] = await db
          .select({ p: authIdentities.providers })
          .from(authIdentities)
          .where(eq(authIdentities.id, dupId))
          .limit(1)
        if (surv && dupRow) {
          await db
            .update(authIdentities)
            .set({ providers: [...(surv.p ?? []), ...(dupRow.p ?? [])] })
            .where(eq(authIdentities.id, survivorId))
        }
        // Global-account merge: repoint ALL of the dup's tenant-scoped rows
        // (across every tenant) before erasing it, so the FK cascade on delete
        // cannot orphan another tenant's credentials/sessions.
        await db.update(authCredentials).set({ identityId: survivorId }).where(eq(authCredentials.identityId, dupId))
        await db.update(authSessions).set({ identityId: survivorId }).where(eq(authSessions.identityId, dupId))
        await db.delete(authIdentities).where(eq(authIdentities.id, dupId))
      },
    },

    credentials: {
      findById: (id, tenantId) =>
        db
          .select()
          .from(authCredentials)
          .where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
          .limit(1)
          .then((r) => r[0] ?? null),

      listByIdentity: (identityId, kind, tenantId) =>
        db
          .select()
          .from(authCredentials)
          .where(
            and(
              eq(authCredentials.identityId, identityId),
              ...(kind ? [eq(authCredentials.kind, kind)] : []),
              ...(tenantId ? [eq(authCredentials.tenantId, tenantId)] : []),
            ),
          ),

      findByProviderSub: (provider, sub) =>
        db
          .select()
          .from(authCredentials)
          .where(
            and(
              sql`${authCredentials.metadata}->>'provider' = ${provider}`,
              sql`${authCredentials.metadata}->>'sub' = ${sub}`,
            ),
          )
          .limit(1)
          .then((r) => r[0] ?? null),

      findByHashedSecret: (secretHash, kind, tenantId) =>
        db
          .select()
          .from(authCredentials)
          .where(
            and(
              eq(authCredentials.secret, secretHash),
              eq(authCredentials.kind, kind),
              tenantWhere(authCredentials, tenantId),
            ),
          )
          .then(pickFreshestCredential),

      insert: (row) =>
        db
          .insert(authCredentials)
          .values(row)
          .then(() => {}),

      updateConditional: (id, patch, expectedVersion, tenantId) =>
        db
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
          .then((r) => r[0] ?? null),

      revoke: (id, revokedAt, tenantId) =>
        db
          .update(authCredentials)
          .set({ revokedAt })
          .where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
          .then(() => {}),

      delete: (id, tenantId) =>
        db
          .delete(authCredentials)
          .where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
          .then(() => {}),

      deleteByKind: (identityId, kind, tenantId) =>
        db
          .delete(authCredentials)
          .where(
            and(
              eq(authCredentials.identityId, identityId),
              eq(authCredentials.kind, kind),
              tenantWhere(authCredentials, tenantId),
            ),
          )
          .then(() => {}),
    },

    sessions: {
      insert: (row) =>
        db
          .insert(authSessions)
          .values(row)
          .then(() => {}),
      findByHash: (sidHash) =>
        db
          .select()
          .from(authSessions)
          .where(eq(authSessions.id, sidHash))
          .limit(1)
          .then((r) => reviveSessionRow(r[0] ?? null)),
      update: (id, patch) =>
        db
          .update(authSessions)
          .set(patch)
          .where(eq(authSessions.id, id))
          .returning()
          .then((r) => reviveSessionRow(r[0] ?? null)),
      delete: (id) =>
        db
          .delete(authSessions)
          .where(eq(authSessions.id, id))
          .then(() => {}),
      listByIdentity: (identityId) =>
        db
          .select()
          .from(authSessions)
          .where(eq(authSessions.identityId, identityId))
          .then((rows) => rows.map((r) => reviveSessionRowRequired(r))),
      deleteAllForIdentity: (identityId) =>
        db
          .delete(authSessions)
          .where(eq(authSessions.identityId, identityId))
          .then(() => {}),
      deleteExpired: (now) =>
        db
          .delete(authSessions)
          .where(lt(authSessions.absoluteExpiresAt, now))
          .returning()
          .then((r) => r.length),
    },
  }

  // One assertion, here, rather than one at every call site: drizzle types the
  // `profile` jsonb column as the base shape, and `Profile` is the caller's
  // refinement of it. Nothing else about the bridge varies with the profile.
  return bridge as SqlBridge.Me<Profile>
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
