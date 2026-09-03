import { createRequire } from 'node:module'
import { and, eq, inArray, isNull, lt, or, sql } from 'drizzle-orm'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import type { PgColumn } from 'drizzle-orm/pg-core'
import {
  assertEmailFree,
  assertProviderSubFree,
  assertRestorable,
  claimedProviderSubs,
  createSqlStores,
  isRestorable,
  pickFreshestCredential,
  profileEmail,
  providerSubKey,
} from '~/adapters/sql'
import type { SqlBridge } from '~/adapters/sql/sql.types'
import { AuthError } from '~/core/errors'
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

/**
 * The question {@link assertRestorable} answers by throwing. `restoreMany` has
 * to ask it per row and keep going, so it needs the predicate rather than the
 * assertion - the batch reports a closed window as one row's soft failure, not
 * as an error that takes the other rows down with it.
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
 * `code` off a driver error, following `cause` because the pool and drizzle
 * both re-wrap what `pg` threw. Narrowed rather than asserted: what arrives here
 * is `unknown`, and a shape that does not carry a code is simply not one of ours.
 */
function driverErrorCode(err: unknown): string | undefined {
  if (typeof err !== 'object' || err === null) return undefined
  if ('code' in err && typeof err.code === 'string') return err.code
  if ('cause' in err) return driverErrorCode(err.cause)
  return undefined
}

/**
 * Postgres raises `22P02` when a value can't cast to a `uuid` column, so an
 * arbitrary string thrown at any id-keyed statement crashes the driver where
 * every other adapter simply misses. An id Postgres cannot represent matches no
 * row by definition, so each path answers with its own "matched nothing" value
 * and lets the store layer turn that into the typed error the contract asks for
 * - `AUTH_STALE_WRITE` on a conditional write, `null` on a read - instead of a
 * driver exception escaping the adapter with a SQL fragment attached.
 */
async function absentOnUnrepresentableId<T>(run: () => Promise<T>, absent: T): Promise<T> {
  try {
    return await run()
  } catch (err) {
    if (driverErrorCode(err) === '22P02') return absent
    throw err
  }
}

const nullOnUnrepresentableId = <T>(read: () => Promise<T | null>): Promise<T | null> =>
  absentOnUnrepresentableId(read, null)

const emptyOnUnrepresentableId = <T>(read: () => Promise<T[]>): Promise<T[]> => absentOnUnrepresentableId(read, [])

/** Generic over the profile so callers with their own profile shape don't have to cast. */
export function createDrizzlePgBridge<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  const TSchema extends Record<string, unknown> = Record<string, unknown>,
>(db: NodePgDatabase<TSchema>): SqlBridge.Me<Profile> {
  /**
   * The provider-link writes are raw `execute` statements, whose `RETURNING`
   * yields unmapped snake_case columns. Re-selecting through the query builder
   * is one more round trip on a rare path and reuses the mapping every other
   * read here already goes through.
   */
  const reselectIdentity = (id: string) =>
    db
      .select()
      .from(authIdentities)
      .where(eq(authIdentities.id, id))
      .limit(1)
      .then((r) => r[0] ?? null)

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
        nullOnUnrepresentableId(() =>
          db
            .update(authIdentities)
            .set(patch)
            .where(and(eq(authIdentities.id, id), eq(authIdentities.version, expectedVersion)))
            .returning()
            .then((r) => r[0] ?? null),
        ),

      softDelete: (id, deletedAt, deletedBy) =>
        // `emailVerified` goes with it: the partial unique index and `findByEmail`
        // both ignore soft-deleted rows, so the address is free to be claimed by
        // someone else during the grace window. Restoring must not hand back a
        // verified claim to an address this identity may no longer control.
        //
        // Live rows only. `deletedAt` is the moment the purge window closes, so
        // a second call on an already-hidden row would push that moment forward
        // and a row could be kept out of reach of the purge indefinitely by
        // repeating a delete that has nothing left to delete.
        nullOnUnrepresentableId(() =>
          db
            .update(authIdentities)
            .set({ deletedAt, deletedBy, emailVerified: false })
            .where(and(eq(authIdentities.id, id), isNull(authIdentities.deletedAt)))
            .returning()
            .then((r) => r[0] ?? null),
        ),

      /**
       * Three round trips, all on a rare admin path: read the hidden row, refuse
       * it if the grace window has closed or its address has since been taken,
       * then clear the marker. Doing the checks here rather than leaning on the
       * partial unique index is what turns a raw driver error into a typed one.
       */
      restore: async (id) => {
        const [row] = await emptyOnUnrepresentableId(() =>
          db.select().from(authIdentities).where(eq(authIdentities.id, id)).limit(1),
        )
        if (!row) return null
        assertRestorable(row)
        const email = profileEmail(row.profile)
        if (email !== undefined) {
          const clash = await db
            .select({ id: authIdentities.id })
            .from(authIdentities)
            .where(
              and(sql`lower(${authIdentities.profile}->>'email') = lower(${email})`, isNull(authIdentities.deletedAt)),
            )
            .limit(1)
          assertEmailFree(email, clash.length > 0)
        }
        // A hidden row's provider logins were free to be claimed the whole time it
        // was invisible, exactly like its email address. `isNull(deletedAt)` also
        // excludes the row being restored, so this only ever finds someone else.
        for (const claim of claimedProviderSubs(row)) {
          const taken = await db
            .select({ id: authIdentities.id })
            .from(authIdentities)
            .where(
              and(
                sql`${authIdentities.providers} @> ${JSON.stringify([{ providerId: claim.providerId, providerSub: claim.providerSub }])}::jsonb`,
                isNull(authIdentities.deletedAt),
              ),
            )
            .limit(1)
          if (taken.length > 0) assertProviderSubFree({ providerId: claim.providerId })
        }
        const restored = await db
          .update(authIdentities)
          .set({ deletedAt: null, deletedBy: null })
          .where(eq(authIdentities.id, id))
          .returning()
        return restored[0] ?? null
      },

      erase: (id) =>
        nullOnUnrepresentableId(async () => {
          await db.delete(authCredentials).where(eq(authCredentials.identityId, id))
          await db.delete(authSessions).where(eq(authSessions.identityId, id))
          // `RETURNING` on the DELETE hands back the row as it was, so saying what
          // was erased costs nothing extra.
          const gone = await db.delete(authIdentities).where(eq(authIdentities.id, id)).returning()
          return gone[0] ?? null
        }),

      /**
       * Appends. This used to drop every existing link sharing the `providerId`
       * before writing the new one, which made a second Google account silently
       * evict the first - one identity legitimately holds several subs under one
       * provider, and no other adapter threw the old one away.
       *
       * The `case` makes an exact repeat of `(providerId, providerSub)` a no-op
       * write rather than a duplicate entry: a retried OAuth callback is the
       * ordinary way this is reached, and containment ignores `addedAt` so the
       * repeat does not re-date the link either. Postgres still counts the row
       * as updated, so `RETURNING` answers with it.
       *
       * The `not exists` is the account-takeover guard, folded into the same
       * statement so there is no window between checking and writing: a
       * `(providerId, providerSub)` pair names one account at the provider, and
       * a second identity claiming one would make `findByProviderSub`
       * non-deterministic about whose session it hands back. Soft-deleted rows
       * do NOT count: `findByProviderSub` already ignores them, so holding a sub
       * against a row nothing can read back would keep someone's provider login
       * hostage forever. `restore` is where a hidden row re-earns its claims,
       * the same as it does for its email. A null sub carries no such identity
       * (every password link has one), so it is exempt.
       */
      insertProviderLink: async (identityId, providerId, providerSub, addedAt) => {
        // Bound as one json string, never interpolated; containment ignores the
        // keys it does not name, so `addedAt` plays no part in matching.
        const held = JSON.stringify([{ providerId, providerSub: providerSub ?? null }])
        const written = await absentOnUnrepresentableId(
          () =>
            db
              .execute(sql`
                update ${authIdentities}
                set providers = case
                  when providers @> ${held}::jsonb then providers
                  else providers || ${JSON.stringify([{ addedAt, providerId, providerSub: providerSub ?? null }])}::jsonb
                end
                where id = ${identityId}
                  ${
                    providerSub === null
                      ? sql``
                      : sql`and not exists (
                          select 1 from ${authIdentities} other
                          where other.id <> ${identityId}
                            and other.deleted_at is null
                            and other.providers @> ${held}::jsonb
                        )`
                  }
                returning id
              `)
              .then((r) => idsOf(r.rows)),
          [],
        )
        if (written.length > 0) return reselectIdentity(identityId)
        // Nothing matched: either the identity is gone - `null`, which is what
        // the store reports as "no such identity" - or the guard above refused
        // the write, which is a conflict the caller has to be told about.
        const cur = await reselectIdentity(identityId)
        if (!cur) return null
        throw new AuthError('AUTH_PROVIDER_FAILED', {
          detail: 'provider sub already linked to a different identity',
          providerId,
        })
      },

      deleteProviderLink: (identityId, providerId) =>
        nullOnUnrepresentableId(async () => {
          await db.execute(sql`
            update ${authIdentities}
            set providers = (
              select coalesce(jsonb_agg(elem), '[]'::jsonb)
              from jsonb_array_elements(providers) elem
              where (elem->>'providerId') != ${providerId}
            )
            where id = ${identityId}
          `)
          return reselectIdentity(identityId)
        }),

      softDeleteManyReturningIds: (ids, deletedAt, deletedBy) =>
        emptyOnUnrepresentableId(() =>
          db
            .update(authIdentities)
            .set({ deletedAt, deletedBy, emailVerified: false })
            .where(and(inArray(authIdentities.id, [...ids]), isNull(authIdentities.deletedAt)))
            .returning({ id: authIdentities.id })
            .then((r) => r.map((x) => x.id)),
        ),

      eraseManyReturningIds: (ids) =>
        emptyOnUnrepresentableId(async () => {
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
        }),

      /**
       * The set-based form of `restore`, and it owes the caller the same two
       * refusals: a row whose grace window has closed is queued for purge, and a
       * row whose address a live identity now holds cannot come back without
       * tripping `uq_auth_identities_email`.
       *
       * Both are per-row decisions, so a row that fails one is left out of the
       * statement rather than throwing - `createSqlStores` reads an id missing
       * from the response as that row's soft failure, which is what keeps one
       * bad id in a batch of fifty from aborting the other forty-nine. Leaning
       * on the unique index instead would abort the whole transaction on the
       * first clash, with a raw driver error rather than a typed one.
       */
      restoreManyReturning: (ids) =>
        // Not `emptyOnUnrepresentableId`: the answer here is a pair of lists,
        // and an id Postgres cannot represent matched neither of them.
        absentOnUnrepresentableId(
          async () => {
            const list = [...ids]
            if (list.length === 0) return { candidates: [], restored: [] }
            const candidates = await db.select().from(authIdentities).where(inArray(authIdentities.id, list))
            const restorable = candidates.filter(isRestorable)
            const emails = new Map<string, string>()
            for (const row of restorable) {
              const email = profileEmail(row.profile)
              if (email !== undefined) emails.set(row.id, email.toLowerCase())
            }
            const taken = new Set<string>()
            if (emails.size > 0) {
              const live = await db
                .select({ profile: authIdentities.profile })
                .from(authIdentities)
                .where(
                  and(
                    inArray(sql`lower(${authIdentities.profile}->>'email')`, [...new Set(emails.values())]),
                    isNull(authIdentities.deletedAt),
                  ),
                )
              for (const row of live) {
                const email = profileEmail(row.profile)
                if (email !== undefined) taken.add(email.toLowerCase())
              }
            }
            // Two hidden rows in one batch can also answer to the same address -
            // the index is partial on `deletedAt`, so nothing kept them apart
            // while both were invisible - and restoring both would be the clash
            // this guard exists to refuse. First one wins.
            // Provider logins clash the same way addresses do, and the batch has to catch
            // it for the same reason the single-row path does: `findByProviderSub` skips
            // hidden rows, so every sub a candidate holds was free to be taken while it
            // was gone.
            const claims = new Map<string, string[]>()
            const allClaims: { providerId: string; providerSub: string }[] = []
            for (const row of restorable) {
              const pairs = claimedProviderSubs(row)
              if (pairs.length === 0) continue
              claims.set(row.id, pairs.map(providerSubKey))
              allClaims.push(...pairs)
            }
            const takenSubs = new Set<string>()
            if (allClaims.length > 0) {
              const holders = await db
                .select({ providers: authIdentities.providers })
                .from(authIdentities)
                .where(
                  and(
                    or(
                      ...allClaims.map(
                        (claim) => sql`${authIdentities.providers} @> ${JSON.stringify([claim])}::jsonb`,
                      ),
                    ),
                    isNull(authIdentities.deletedAt),
                  ),
                )
              // Every sub a matched live row holds, not just the one that matched: they
              // are all genuinely spoken for by a row that is visible right now.
              for (const holder of holders) {
                for (const pair of claimedProviderSubs(holder)) takenSubs.add(providerSubKey(pair))
              }
            }
            const okIds: string[] = []
            const refused: { id: string; reason: 'email-taken' | 'provider-taken' }[] = []
            for (const row of restorable) {
              const email = emails.get(row.id)
              const keys = claims.get(row.id)
              // Both checks before either commit: a row refused for its address must not
              // go on to reserve its provider subs against later rows.
              if (email !== undefined && taken.has(email)) {
                refused.push({ id: row.id, reason: 'email-taken' })
                continue
              }
              if (keys?.some((key) => takenSubs.has(key))) {
                refused.push({ id: row.id, reason: 'provider-taken' })
                continue
              }
              if (email !== undefined) taken.add(email)
              if (keys !== undefined) for (const key of keys) takenSubs.add(key)
              okIds.push(row.id)
            }
            if (okIds.length === 0) return { candidates, refused, restored: [] }
            const restored = await db
              .update(authIdentities)
              .set({ deletedAt: null, deletedBy: null })
              .where(inArray(authIdentities.id, okIds))
              .returning()
            return { candidates, refused, restored }
          },
          { candidates: [], restored: [] },
        ),

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
      updateProfileManyReturning: (rows) =>
        emptyOnUnrepresentableId(async () => {
          if (rows.length === 0) return []
          const values = sql.join(
            rows.map(
              (r) =>
                sql`(${r.id}::uuid, ${JSON.stringify(r.patch.profile)}::jsonb, ${r.patch.updatedAt ?? new Date()}::timestamptz, ${r.patch.updatedBy ?? null}::text, ${r.patch.version ?? r.expectedVersion + 1}::integer, ${r.expectedVersion}::integer)`,
            ),
            sql`, `,
          )
          const updated = await db.execute(sql`
            update ${authIdentities} as t
            set profile = v.profile, updated_at = v.updated_at, updated_by = v.updated_by, version = v.version
            from (values ${values}) as v(id, profile, updated_at, updated_by, version, expected_version)
            where t.id = v.id and t.version = v.expected_version
            returning t.id
          `)
          const ids = idsOf(updated.rows)
          if (ids.length === 0) return []
          return db.select().from(authIdentities).where(inArray(authIdentities.id, ids))
        }),

      merge: (survivorId, dupId) =>
        nullOnUnrepresentableId(async () => {
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
          // Both sides must exist BEFORE anything is written: the steps below
          // re-point the dup's credentials and sessions and then delete it, so a
          // survivor that is not there turns a merge into silent data loss. The
          // memory adapter has always refused this; so does every dialect.
          if (!surv || !dupRow) return null
          // Merging a row into itself has nothing to move and one row to keep.
          // Run the steps below on it and the last of them deletes the survivor,
          // so a caller that passed the same id twice - a resolved duplicate
          // that was never a duplicate - would lose the account it meant to keep.
          if (survivorId === dupId) return reselectIdentity(survivorId)
          await db
            .update(authIdentities)
            .set({ providers: [...(surv.p ?? []), ...(dupRow.p ?? [])] })
            .where(eq(authIdentities.id, survivorId))
          // Repoint all of the dup's rows across every tenant before erasing it, so the
          // FK cascade on delete cannot orphan another tenant's credentials/sessions.
          await db.update(authCredentials).set({ identityId: survivorId }).where(eq(authCredentials.identityId, dupId))
          await db.update(authSessions).set({ identityId: survivorId }).where(eq(authSessions.identityId, dupId))
          await db.delete(authIdentities).where(eq(authIdentities.id, dupId))
          // The survivor is what the caller keeps; `null` when there was none.
          return reselectIdentity(survivorId)
        }),
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
        emptyOnUnrepresentableId(() =>
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
        ),

      // `provider`/`sub` live in the free-form `metadata` of an oauth row, and
      // nothing stops another kind from carrying the same two keys - an api-key
      // whose metadata records which provider minted it would answer an oauth
      // lookup. Both filters are the ones the caller already believes are on:
      // one tenant's oauth rows, and only oauth rows.
      findByProviderSub: (provider, sub, tenantId) =>
        db
          .select()
          .from(authCredentials)
          .where(
            and(
              eq(authCredentials.kind, 'oauth'),
              sql`${authCredentials.metadata}->>'provider' = ${provider}`,
              sql`${authCredentials.metadata}->>'sub' = ${sub}`,
              tenantWhere(authCredentials, tenantId),
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
        nullOnUnrepresentableId(() =>
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
        ),

      revoke: (id, revokedAt, tenantId) =>
        nullOnUnrepresentableId(() =>
          db
            .update(authCredentials)
            .set({ revokedAt })
            .where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
            .returning()
            .then((r) => r[0] ?? null),
        ),

      delete: (id, tenantId) =>
        nullOnUnrepresentableId(() =>
          db
            .delete(authCredentials)
            .where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
            .returning()
            .then((r) => r[0] ?? null),
        ),

      deleteByIdentitiesReturningIds: (identityIds, tenantId) =>
        emptyOnUnrepresentableId(() =>
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
        ),

      deleteByKind: (identityId, kind, tenantId) =>
        emptyOnUnrepresentableId(() =>
          db
            .delete(authCredentials)
            .where(
              and(
                eq(authCredentials.identityId, identityId),
                eq(authCredentials.kind, kind),
                tenantWhere(authCredentials, tenantId),
              ),
            )
            .returning(),
        ),
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
      // A patch whose every key was an explicit `undefined` arrives here empty,
      // and drizzle refuses an `UPDATE` with nothing to set. "Change none of
      // these fields" is a read, not an error: the memory store hands the row
      // back untouched and so does this.
      update: (id, patch) =>
        Object.keys(patch).length === 0
          ? db
              .select()
              .from(authSessions)
              .where(eq(authSessions.id, id))
              .limit(1)
              .then((r) => reviveSessionRow(r[0] ?? null))
          : db
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
        emptyOnUnrepresentableId(() =>
          db
            .select()
            .from(authSessions)
            .where(eq(authSessions.identityId, identityId))
            .then((rows) => rows.map((r) => reviveSessionRowRequired(r))),
        ),
      deleteAllForIdentity: async (identityId) => {
        await nullOnUnrepresentableId(async () => {
          await db.delete(authSessions).where(eq(authSessions.identityId, identityId))
          return null
        })
      },
      deleteAllForIdentitiesReturningIds: (identityIds) =>
        emptyOnUnrepresentableId(() =>
          db
            .delete(authSessions)
            .where(inArray(authSessions.identityId, [...identityIds]))
            .returning({ id: authSessions.identityId })
            .then((r) => r.map((x) => x.id).filter((id): id is string => id !== null)),
        ),

      deleteManyReturningIds: (ids) =>
        db
          .delete(authSessions)
          .where(inArray(authSessions.id, [...ids]))
          .returning({ id: authSessions.id })
          .then((r) => r.map((x) => x.id)),

      listByIdentities: (identityIds) =>
        emptyOnUnrepresentableId(() =>
          db
            .select()
            .from(authSessions)
            .where(inArray(authSessions.identityId, [...identityIds]))
            .then((rows) => rows.map(reviveSessionRowRequired)),
        ),

      // Either clock, not just the outer one. `expiresAt` is the idle deadline a
      // session is renewed against and `absoluteExpiresAt` the ceiling it can
      // never pass; reading only the ceiling left every idled-out session in the
      // table until its absolute deadline, hours or days later.
      deleteExpired: (now) =>
        db
          .delete(authSessions)
          .where(or(lt(authSessions.expiresAt, now), lt(authSessions.absoluteExpiresAt, now)))
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
