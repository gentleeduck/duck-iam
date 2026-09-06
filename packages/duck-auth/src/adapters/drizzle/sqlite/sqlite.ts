/**
 * Drizzle (SQLite) implementation of the {@link SqlBridge} contract. Driver-agnostic:
 * works with better-sqlite3, libsql/Turso, or bun:sqlite. SQLite has no jsonb
 * containment operator, so provider-link lookups use `json_each` and link edits are
 * read-modify-write at the bridge boundary. Queries are tenant-scoped when `tenantId`
 * is passed; `undefined` skips the filter.
 */

import { createRequire } from 'node:module'
import { and, eq, inArray, isNull, lt, ne, or, sql } from 'drizzle-orm'
import type { BaseSQLiteDatabase, SQLiteColumn } from 'drizzle-orm/sqlite-core'
import {
  assertEmailFree,
  assertRestorable,
  createSqlStores,
  isRestorable,
  pickFreshestCredential,
  profileEmail,
} from '~/adapters/sql'
import type { SqlBridge } from '~/adapters/sql/sql.types'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import { authCredentials, authIdentities, authSessions } from './sqlite.schema'
import type { Sqlite } from './sqlite.types'

/**
 * The question {@link assertRestorable} answers by throwing. `restoreMany` has
 * to ask it per row and keep going, so it needs the predicate rather than the
 * assertion - the batch reports a closed window as one row's soft failure, not
 * as an error that takes the other rows down with it.
 */
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
        // `emailVerified` goes with it: the partial unique index and `findByEmail`
        // both ignore soft-deleted rows, so the address is free to be claimed by
        // someone else during the grace window. Restoring must not hand back a
        // verified claim to an address this identity may no longer control.
        //
        // Live rows only. `deletedAt` is the moment the purge window closes, so
        // a second call on an already-hidden row would push that moment forward
        // and a row could be kept out of reach of the purge indefinitely by
        // repeating a delete that has nothing left to delete.
        const result = await db
          .update(authIdentities)
          .set({ deletedAt, emailVerified: false })
          .where(and(eq(authIdentities.id, id), isNull(authIdentities.deletedAt)))
          .returning()
        return result[0] ?? null
      },
      /**
       * Three round trips, all on a rare admin path: read the hidden row, refuse
       * it if the grace window has closed or its address has since been taken,
       * then clear the marker. Doing the checks here rather than leaning on the
       * partial unique index is what turns a raw driver error into a typed one.
       */
      restore: async (id) => {
        const [row] = await db.select().from(authIdentities).where(eq(authIdentities.id, id)).limit(1)
        if (!row) return null
        assertRestorable(row)
        const email = profileEmail(row.profile)
        if (email !== undefined) {
          const clash = await db
            .select({ id: authIdentities.id })
            .from(authIdentities)
            .where(
              and(
                sql`lower(json_extract(${authIdentities.profile}, '$.email')) = lower(${email})`,
                isNull(authIdentities.deletedAt),
              ),
            )
            .limit(1)
          assertEmailFree(email, clash.length > 0)
        }
        const result = await db
          .update(authIdentities)
          .set({ deletedAt: null })
          .where(eq(authIdentities.id, id))
          .returning()
        return result[0] ?? null
      },
      erase: async (id) => {
        // FK CASCADE handles credentials and sessions; explicit deletes are belt-and-suspenders.
        await db.delete(authCredentials).where(eq(authCredentials.identityId, id))
        await db.delete(authSessions).where(eq(authSessions.identityId, id))
        // `RETURNING` on the DELETE hands back the row as it was, so saying what
        // was erased costs nothing extra.
        const gone = await db
          .delete(authIdentities)
          .where(and(eq(authIdentities.id, id)))
          .returning()
        return gone[0] ?? null
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt) => {
        // Read-modify-write: SQLite JSON edit functions are awkward; splice client-side.
        const rows = await db
          .select({ providers: authIdentities.providers })
          .from(authIdentities)
          .where(and(eq(authIdentities.id, identityId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return null
        // A `(providerId, providerSub)` pair identifies one account at the
        // provider, so letting a second identity claim one is account takeover:
        // sign in as the attacker, link the victim's Google sub, and the next
        // `findByProviderSub` may hand the victim's session to either row.
        // Soft-deleted rows do NOT count: `findByProviderSub` already ignores
        // them, so holding a sub against a row nothing can read back would keep
        // someone's provider login hostage forever. `restore` is where a hidden
        // row re-earns its claims, the same as it does for its email.
        if (providerSub !== null) {
          const held = await db
            .select({ id: authIdentities.id })
            .from(authIdentities)
            .where(
              and(
                ne(authIdentities.id, identityId),
                isNull(authIdentities.deletedAt),
                sql`exists (
                  select 1 from json_each(${authIdentities.providers}) je
                  where json_extract(je.value, '$.providerId') = ${providerId}
                    and json_extract(je.value, '$.providerSub') = ${providerSub}
                )`,
              ),
            )
            .limit(1)
          if (held.length > 0) {
            throw new AuthError('AUTH_PROVIDER_FAILED', {
              detail: 'provider sub already linked to a different identity',
              providerId,
            })
          }
        }
        const providers = cur.providers ?? []
        // Already linked: nothing to write, but the row still exists and it
        // already carries the link, so answer with it rather than with `null`.
        if (providers.some((p) => p.providerId === providerId && p.providerSub === providerSub)) {
          const [unchanged] = await db.select().from(authIdentities).where(eq(authIdentities.id, identityId)).limit(1)
          return unchanged ?? null
        }
        providers.push({ providerId, providerSub: providerSub ?? null, addedAt })
        const linked = await db
          .update(authIdentities)
          .set({ providers })
          .where(and(eq(authIdentities.id, identityId)))
          .returning()
        return linked[0] ?? null
      },
      deleteProviderLink: async (identityId, providerId) => {
        const rows = await db
          .select({ providers: authIdentities.providers })
          .from(authIdentities)
          .where(and(eq(authIdentities.id, identityId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return null
        const providers = (cur.providers ?? []).filter((p) => p.providerId !== providerId)
        const unlinked = await db
          .update(authIdentities)
          .set({ providers })
          .where(and(eq(authIdentities.id, identityId)))
          .returning()
        return unlinked[0] ?? null
      },
      softDeleteManyReturningIds: async (ids, deletedAt) => {
        const rows = await db
          .update(authIdentities)
          .set({ deletedAt, emailVerified: false })
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

      /**
       * The set-based form of `restore`, and it owes the caller the same two
       * refusals: a row whose grace window has closed is queued for purge, and a
       * row whose address a live identity now holds cannot come back without
       * two live rows answering to one email.
       *
       * Both are per-row decisions, so a row that fails one is left out of the
       * statement rather than throwing - `createSqlStores` reads an id missing
       * from the response as that row's soft failure, which is what keeps one
       * bad id in a batch of fifty from aborting the other forty-nine.
       */
      restoreManyReturning: async (ids) => {
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
                inArray(sql`lower(json_extract(${authIdentities.profile}, '$.email'))`, [...new Set(emails.values())]),
                isNull(authIdentities.deletedAt),
              ),
            )
          for (const row of live) {
            const email = profileEmail(row.profile)
            if (email !== undefined) taken.add(email.toLowerCase())
          }
        }
        // Two hidden rows in one batch can also answer to the same address -
        // nothing kept them apart while both were invisible - so an address
        // claimed by an earlier row in this batch is taken for the rest of it.
        const okIds: string[] = []
        for (const row of restorable) {
          const email = emails.get(row.id)
          if (email !== undefined) {
            if (taken.has(email)) continue
            taken.add(email)
          }
          okIds.push(row.id)
        }
        if (okIds.length === 0) return { candidates, restored: [] }
        const restored = await db
          .update(authIdentities)
          .set({ deletedAt: null })
          .where(inArray(authIdentities.id, okIds))
          .returning()
        return { candidates, restored }
      },

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
        // Both sides must exist BEFORE anything is written: the steps below
        // re-point the dup's credentials and sessions and then delete it, so a
        // survivor that is not there turns a merge into silent data loss. The
        // memory adapter has always refused this; so does every dialect.
        if (!surv || !dupRow) return null
        // Merging a row into itself has nothing to move and one row to keep. Run
        // the steps below on it and the last of them deletes the survivor, so a
        // caller that passed the same id twice - a resolved duplicate that was
        // never a duplicate - would lose the account it was trying to keep.
        if (survivorId === dupId) {
          const [self] = await db.select().from(authIdentities).where(eq(authIdentities.id, survivorId)).limit(1)
          return self ?? null
        }
        await db
          .update(authIdentities)
          .set({ providers: [...(surv.providers ?? []), ...(dupRow.providers ?? [])] })
          .where(eq(authIdentities.id, survivorId))
        // Repoint all of the dup's rows across every tenant before erasing it, so the
        // FK cascade on delete cannot orphan another tenant's credentials/sessions.
        await db.update(authCredentials).set({ identityId: survivorId }).where(eq(authCredentials.identityId, dupId))
        await db.update(authSessions).set({ identityId: survivorId }).where(eq(authSessions.identityId, dupId))
        await db.delete(authIdentities).where(eq(authIdentities.id, dupId))
        // The survivor is what the caller keeps; `null` when there was none.
        const [merged] = await db.select().from(authIdentities).where(eq(authIdentities.id, survivorId)).limit(1)
        return merged ?? null
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
      // `provider`/`sub` live in the free-form `metadata` of an oauth row, and
      // nothing stops another kind from carrying the same two keys - an api-key
      // whose metadata records which provider minted it would answer an oauth
      // lookup. Both filters are the ones the caller already believes are on:
      // one tenant's oauth rows, and only oauth rows.
      findByProviderSub: async (provider, sub, tenantId) => {
        const rows = await db
          .select()
          .from(authCredentials)
          .where(
            and(
              eq(authCredentials.kind, 'oauth'),
              sql`json_extract(${authCredentials.metadata}, '$.provider') = ${provider}`,
              sql`json_extract(${authCredentials.metadata}, '$.sub') = ${sub}`,
              tenantWhere(authCredentials, tenantId),
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
        const result = await db
          .update(authCredentials)
          .set({ revokedAt })
          .where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
          .returning()
        return result[0] ?? null
      },
      delete: async (id, tenantId) => {
        const gone = await db
          .delete(authCredentials)
          .where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
          .returning()
        return gone[0] ?? null
      },
      deleteByIdentitiesReturningIds: async (identityIds, tenantId) => {
        const rows = await db
          .delete(authCredentials)
          .where(and(inArray(authCredentials.identityId, [...identityIds]), tenantWhere(authCredentials, tenantId)))
          .returning({ id: authCredentials.identityId })
        return rows.map((r) => r.id).filter((id): id is string => id !== null)
      },
      deleteByKind: async (identityId, kind, tenantId) => {
        return db
          .delete(authCredentials)
          .where(
            and(
              eq(authCredentials.identityId, identityId),
              eq(authCredentials.kind, kind),
              tenantWhere(authCredentials, tenantId),
            ),
          )
          .returning()
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
        // A patch whose every key was an explicit `undefined` arrives here
        // empty, and drizzle refuses an `UPDATE` with nothing to set. "Change
        // none of these fields" is a read, not an error: the memory store hands
        // the row back untouched and so does this.
        if (Object.keys(patch).length === 0) {
          const rows = await db.select().from(authSessions).where(eq(authSessions.id, id)).limit(1)
          return rows[0] ?? null
        }
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
      // Either clock, not just the outer one. `expiresAt` is the idle deadline a
      // session is renewed against and `absoluteExpiresAt` the ceiling it can
      // never pass; reading only the ceiling left every idled-out session in the
      // table until its absolute deadline, hours or days later.
      deleteExpired: async (now) => {
        const result = await db
          .delete(authSessions)
          .where(or(lt(authSessions.expiresAt, now), lt(authSessions.absoluteExpiresAt, now)))
          .returning()
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
