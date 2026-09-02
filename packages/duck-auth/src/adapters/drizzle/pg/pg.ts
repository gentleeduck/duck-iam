import { createRequire } from 'node:module'
import { and, eq, inArray, isNull, lt, sql } from 'drizzle-orm'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import type { PgColumn } from 'drizzle-orm/pg-core'
import { createSqlStores, pickFreshestCredential } from '~/adapters/sql'
import type { SqlBridge } from '~/adapters/sql/sql.types'
import type { Identities } from '~/core/identities'
import { authCredentials, authIdentities, authSessions } from './pg.schema'
import type { Pg } from './pg.types'

/**
 * Postgres returns `jsonb` as already-parsed JSON, so `Date` fields nested inside
 * `factors`/`actingAs` come back as ISO strings; revive them so `Sessions.Me` satisfies
 * its `Date`-typed contract. Top-level timestamptz columns are already `Date`.
 */
/**
 * Pull the `id` column out of a raw `db.execute` result. `execute` hands back
 * untyped rows, so narrow rather than assert - a row without a string id is
 * dropped instead of becoming `undefined` in the caller's outcome list.
 */
function idsOf(rows: readonly Record<string, unknown>[]): string[] {
  const out: string[] = []
  for (const row of rows) {
    if (typeof row.id === 'string') out.push(row.id)
  }
  return out
}

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
 * Postgres raises `22P02` when a value can't cast to a `uuid` column, so an arbitrary
 * string thrown at a primary-key lookup crashes instead of returning null like every
 * other adapter. Treat an unrepresentable id as absent to avoid leaking a SQL error.
 */
async function nullOnUnrepresentableId<T>(read: () => Promise<T | null>): Promise<T | null> {
  try {
    return await read()
  } catch (err) {
    const code =
      (err as { code?: string; cause?: { code?: string } })?.code ?? (err as { cause?: { code?: string } })?.cause?.code
    if (code === '22P02') return null
    throw err
  }
}

/** Generic over the profile so callers with their own profile shape don't have to cast. */
export function createDrizzlePgBridge<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  const TSchema extends Record<string, unknown> = Record<string, unknown>,
>(db: NodePgDatabase<TSchema>): SqlBridge.Me<Profile> {
  const tenantWhere = <T extends { tenantId: PgColumn }>(table: T, tenantId: string | undefined) =>
    tenantId === undefined ? undefined : eq(table.tenantId, tenantId)

  const bridge: SqlBridge.Me = {
    identities: {
      findById: (id) =>
        nullOnUnrepresentableId(() =>
          db
            .select()
            .from(authIdentities)
            .where(and(eq(authIdentities.id, id), isNull(authIdentities.deletedAt)))
            .limit(1)
            .then((r) => r[0] ?? null),
        ),

      // Case-insensitive to match the `unique (lower(profile->>'email'))` constraint.
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
              sql`${authIdentities.providers} @> ${JSON.stringify([{ providerId, providerSub: sub }])}::jsonb`,
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
          ) || ${JSON.stringify([{ providerId, providerSub: providerSub ?? null, addedAt }])}::jsonb
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

      softDeleteManyReturningIds: (ids, deletedAt) =>
        db
          .update(authIdentities)
          .set({ deletedAt })
          .where(and(inArray(authIdentities.id, [...ids]), isNull(authIdentities.deletedAt)))
          .returning({ id: authIdentities.id })
          .then((r) => r.map((x) => x.id)),

      eraseManyReturningIds: async (ids) => {
        const list = [...ids]
        // Children first: `auth_credentials`/`auth_sessions` reference the
        // identity, exactly as the single-row `erase` above does.
        await db.delete(authCredentials).where(inArray(authCredentials.identityId, list))
        await db.delete(authSessions).where(inArray(authSessions.identityId, list))
        const gone = await db
          .delete(authIdentities)
          .where(inArray(authIdentities.id, list))
          .returning({ id: authIdentities.id })
        return gone.map((x) => x.id)
      },

      restoreManyReturning: (ids) =>
        db
          .update(authIdentities)
          .set({ deletedAt: null })
          .where(inArray(authIdentities.id, [...ids]))
          .returning(),

      /**
       * One set-based `UPDATE ... FROM (VALUES ...)` so every row is matched on
       * its OWN expected version in a single statement, then one `SELECT` to
       * read the survivors back through the query builder.
       *
       * The `id` column is `uuid`, so the VALUES id is cast to `uuid` too - cast
       * it to `text` and Postgres reports "no operator matches" for `t.id = v.id`
       * rather than silently comparing nothing.
       *
       * Two statements rather than one `RETURNING t.*`, because `execute` yields
       * raw snake_case columns that would have to be re-mapped by hand; a second
       * set-based select is still O(1) statements per batch, and it reuses the
       * mapping every other read here already goes through.
       */
      updateProfileManyReturning: async (rows) => {
        if (rows.length === 0) return []
        const values = sql.join(
          rows.map(
            (r) =>
              sql`(${r.id}::uuid, ${JSON.stringify(r.patch.profile)}::jsonb, ${r.patch.updatedAt ?? new Date()}::timestamptz, ${r.patch.version ?? r.expectedVersion + 1}::integer, ${r.expectedVersion}::integer)`,
          ),
          sql`, `,
        )
        const updated = await db.execute(sql`
          update ${authIdentities} as t
          set profile = v.profile, updated_at = v.updated_at, version = v.version
          from (values ${values}) as v(id, profile, updated_at, version, expected_version)
          where t.id = v.id and t.version = v.expected_version
          returning t.id
        `)
        const ids = idsOf(updated.rows)
        if (ids.length === 0) return []
        return db.select().from(authIdentities).where(inArray(authIdentities.id, ids))
      },

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
        // Repoint all of the dup's rows across every tenant before erasing it, so the
        // FK cascade on delete cannot orphan another tenant's credentials/sessions.
        await db.update(authCredentials).set({ identityId: survivorId }).where(eq(authCredentials.identityId, dupId))
        await db.update(authSessions).set({ identityId: survivorId }).where(eq(authSessions.identityId, dupId))
        await db.delete(authIdentities).where(eq(authIdentities.id, dupId))
      },
    },

    credentials: {
      findById: (id, tenantId) =>
        nullOnUnrepresentableId(() =>
          db
            .select()
            .from(authCredentials)
            .where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
            .limit(1)
            .then((r) => r[0] ?? null),
        ),

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

      deleteByIdentitiesReturningIds: (identityIds, tenantId) =>
        db
          .delete(authCredentials)
          .where(
            and(
              inArray(authCredentials.identityId, [...identityIds]),
              tenantId === undefined ? undefined : eq(authCredentials.tenantId, tenantId),
            ),
          )
          .returning({ id: authCredentials.identityId })
          .then((r) => r.map((x) => x.id)),

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
      deleteAllForIdentitiesReturningIds: (identityIds) =>
        db
          .delete(authSessions)
          .where(inArray(authSessions.identityId, [...identityIds]))
          .returning({ id: authSessions.identityId })
          .then((r) => r.map((x) => x.id).filter((id): id is string => id !== null)),

      deleteManyReturningIds: (ids) =>
        db
          .delete(authSessions)
          .where(inArray(authSessions.id, [...ids]))
          .returning({ id: authSessions.id })
          .then((r) => r.map((x) => x.id)),

      listByIdentities: (identityIds) =>
        db
          .select()
          .from(authSessions)
          .where(inArray(authSessions.identityId, [...identityIds]))
          .then((rows) => rows.map(reviveSessionRowRequired)),

      deleteExpired: (now) =>
        db
          .delete(authSessions)
          .where(lt(authSessions.absoluteExpiresAt, now))
          .returning()
          .then((r) => r.length),
    },
    /**
     * Re-make this bridge against `client` - a drizzle transaction handle,
     * which is structurally the same database surface for every query builder
     * this bridge uses. The assertion is the boundary where an opaque client
     * re-enters the driver's own type, and belongs here rather than in `core/`
     * precisely because this file is the only one that knows the driver.
     */
    withClient: (client) => createDrizzlePgBridge<Profile, TSchema>(client as NodePgDatabase<TSchema>),
  }

  // One assertion here instead of one at every call site: drizzle types `profile` as
  // the base shape, and `Profile` is the caller's refinement of it.
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
