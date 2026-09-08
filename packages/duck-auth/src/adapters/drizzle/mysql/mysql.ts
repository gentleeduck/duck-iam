/**
 * Drizzle (MySQL / MariaDB) implementation of the {@link SqlBridge} contract. MySQL has
 * no `RETURNING`, so mutations that must return the new row re-`SELECT` it, and JSON
 * lookups use `->>'$.key'`/`JSON_CONTAINS` instead of pg's `->>`/`@>`. Queries are
 * tenant-scoped when `tenantId` is passed; `undefined` skips the filter.
 */

import { createRequire } from 'node:module'
import { and, eq, getTableColumns, inArray, isNotNull, isNull, lt, ne, or, sql } from 'drizzle-orm'
import type { MySqlColumn } from 'drizzle-orm/mysql-core'
import type { MySql2Database } from 'drizzle-orm/mysql2'
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
import {
  reviveIdentityRow,
  reviveIdentityRowOrNull,
  reviveSessionRow,
  reviveSessionRowRequired,
  type StoredProviderLink,
} from '~/adapters/sql/stored-json'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities'
import { authCredentials, authIdentities, authSessions } from './mysql.schema'

/**
 * Every session of one identity, narrowed to a tenant when one is named.
 *
 * `eq` never matches NULL, so a global (`tenant_id IS NULL`) session is
 * deliberately outside a named tenant's scope - the same rule the credential
 * queries follow, and the reason a tenant's "sign out everywhere" can no longer
 * reach the same person's logins in another tenant. `auth_sessions_tenant`
 * indexes the column, and `identity_id` is indexed too.
 */
function sessionScope(identityId: string, tenantId: string | undefined) {
  return tenantId === undefined
    ? eq(authSessions.identityId, identityId)
    : and(eq(authSessions.identityId, identityId), eq(authSessions.tenantId, tenantId))
}

import type { Mysql } from './mysql.types'

/**
 * The question {@link assertRestorable} answers by throwing. `restoreMany` has
 * to ask it per row and keep going, so it needs the predicate rather than the
 * assertion - the batch reports a closed window as one row's soft failure, not
 * as an error that takes the other rows down with it.
 */
/**
 * Every read-modify-write here pins its `UPDATE` to the state the read saw, and
 * this is that predicate for the `providers` array. MySQL compares two `json`
 * values semantically, so re-serialising what came back matches the stored
 * document whatever order the server chose to keep its keys in.
 *
 * Without it the two statements are a lost-update race: two links added at once
 * both read one array, both write their own, and the second silently erases the
 * first - a provider the user believes is connected and is not.
 */
const providersUnchanged = (seen: readonly StoredProviderLink[]) =>
  sql`${authIdentities.providers} = cast(${JSON.stringify(seen)} as json)`

/** A write that matched nothing after its own read saw the row: someone else got there first. */
const staleWrite = (): AuthError => new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: -1 })

/** Generic over the profile so callers with their own profile shape don't have to cast. */
export function createDrizzleMysqlBridge<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  const TSchema extends Record<string, unknown> = Record<string, unknown>,
>(db: MySql2Database<TSchema>): SqlBridge.Me<Profile> {
  /** Scope a where clause by tenantId; undefined tenant skips the filter. */
  function tenantWhere<T extends { tenantId: MySqlColumn }>(table: T, tenantId: string | undefined) {
    return tenantId === undefined ? undefined : eq(table.tenantId, tenantId)
  }

  /**
   * The row contract's columns: everything on the table except the two
   * generated index carriers. A bare `select()` would return those too, and
   * they would ride out to consumers as fields of `Identities.Me`.
   */
  const { emailNorm: _emailNorm, usernameNorm: _usernameNorm, ...identityColumns } = getTableColumns(authIdentities)

  /** MySQL has no RETURNING, so re-select a row by primary key after a mutation. */
  async function reselectIdentity(id: string) {
    const rows = await db.select(identityColumns).from(authIdentities).where(eq(authIdentities.id, id)).limit(1)
    return reviveIdentityRowOrNull(rows[0] ?? null)
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
          .select(identityColumns)
          .from(authIdentities)
          .where(and(eq(authIdentities.id, id), isNull(authIdentities.deletedAt)))
          .limit(1)
        const row = rows[0]
        if (!row) return null
        return reviveIdentityRow(row)
      },
      findByEmail: async (email) => {
        const rows = await db
          .select(identityColumns)
          .from(authIdentities)
          .where(
            and(sql`lower(${authIdentities.profile}->>'$.email') = lower(${email})`, isNull(authIdentities.deletedAt)),
          )
          .limit(1)
        return reviveIdentityRowOrNull(rows[0] ?? null)
      },
      findByProviderSub: async (providerId, sub) => {
        // JSON_CONTAINS(target, candidate); needle is bound as a parameter, never interpolated.
        const needle = JSON.stringify({ providerId, providerSub: sub })
        const rows = await db
          .select(identityColumns)
          .from(authIdentities)
          .where(and(sql`json_contains(${authIdentities.providers}, ${needle})`, isNull(authIdentities.deletedAt)))
          .limit(1)
        return reviveIdentityRowOrNull(rows[0] ?? null)
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
      softDelete: async (id, deletedAt, deletedBy) => {
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
          .set({ deletedAt, deletedBy, emailVerified: false })
          .where(and(eq(authIdentities.id, id), isNull(authIdentities.deletedAt)))
        if (result[0].affectedRows === 0) return null
        return reselectIdentity(id)
      },
      /**
       * Three round trips, all on a rare admin path: read the hidden row, refuse
       * it if the grace window has closed or its address has since been taken,
       * then clear the marker. Doing the checks here rather than leaning on the
       * partial unique index is what turns a raw driver error into a typed one.
       */
      restore: async (id) => {
        const row = await reselectIdentity(id)
        if (!row) return null
        assertRestorable(row)
        const email = profileEmail(row.profile)
        if (email !== undefined) {
          const clash = await db
            .select({ id: authIdentities.id })
            .from(authIdentities)
            .where(
              and(
                sql`lower(${authIdentities.profile}->>'$.email') = lower(${email})`,
                isNull(authIdentities.deletedAt),
              ),
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
                sql`json_contains(${authIdentities.providers}, ${JSON.stringify({ providerId: claim.providerId, providerSub: claim.providerSub })})`,
                isNull(authIdentities.deletedAt),
              ),
            )
            .limit(1)
          if (taken.length > 0) assertProviderSubFree({ providerId: claim.providerId })
        }
        // `assertRestorable` has already refused a null; naming the value is
        // what lets the write below pin itself to the row the checks were made
        // against, rather than to whatever the row has become since.
        const closesAt = row.deletedAt
        if (closesAt === null) throw staleWrite()
        const result = await db
          .update(authIdentities)
          .set({ deletedAt: null, deletedBy: null })
          .where(and(eq(authIdentities.id, id), eq(authIdentities.deletedAt, closesAt)))
        if (result[0].affectedRows === 0) throw staleWrite()
        return reselectIdentity(id)
      },
      erase: async (id) => {
        // Read first: the row is gone by the time the caller is answered, so
        // this is the only chance to say what was erased.
        const row = await reselectIdentity(id)
        // FK CASCADE handles credentials and sessions; explicit deletes are belt-and-suspenders.
        await db.delete(authCredentials).where(eq(authCredentials.identityId, id))
        await db.delete(authSessions).where(eq(authSessions.identityId, id))
        await db.delete(authIdentities).where(and(eq(authIdentities.id, id)))
        return row
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt) => {
        // Read-modify-write: portable across MySQL 5.7/8.x/MariaDB; splice client-side.
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
        // row re-earns its claims, the same as it does for its email. A null sub
        // names no account (every password link has one), so it is exempt.
        if (providerSub !== null) {
          const held = await db
            .select({ id: authIdentities.id })
            .from(authIdentities)
            .where(
              and(
                ne(authIdentities.id, identityId),
                isNull(authIdentities.deletedAt),
                sql`json_contains(${authIdentities.providers}, ${JSON.stringify({ providerId, providerSub })})`,
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
        const seen = cur.providers ?? []
        // Already linked: nothing to write, but the row still exists and it
        // already carries the link, so answer with it rather than with `null`.
        if (seen.some((p) => p.providerId === providerId && p.providerSub === providerSub)) {
          return reselectIdentity(identityId)
        }
        const result = await db
          .update(authIdentities)
          .set({ providers: [...seen, { addedAt, providerId, providerSub: providerSub ?? null }] })
          .where(and(eq(authIdentities.id, identityId), providersUnchanged(seen)))
        if (result[0].affectedRows === 0) throw staleWrite()
        return reselectIdentity(identityId)
      },
      deleteProviderLink: async (identityId, providerId) => {
        const rows = await db
          .select({ providers: authIdentities.providers })
          .from(authIdentities)
          .where(and(eq(authIdentities.id, identityId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return null
        const seen = cur.providers ?? []
        const providers = seen.filter((p) => p.providerId !== providerId)
        // Nothing to remove. Worth its own branch rather than writing the array
        // back unchanged: MySQL counts an UPDATE that changes nothing as zero
        // rows affected, which the pinned write below would read as a lost race.
        if (providers.length === seen.length) return reselectIdentity(identityId)
        const result = await db
          .update(authIdentities)
          .set({ providers })
          .where(and(eq(authIdentities.id, identityId), providersUnchanged(seen)))
        if (result[0].affectedRows === 0) throw staleWrite()
        return reselectIdentity(identityId)
      },
      /**
       * MySQL has no `RETURNING`, so every set-based write here reads the
       * matching ids FIRST and then writes them. Both statements run on one
       * connection - inside the caller's transaction when there is one - so the
       * read cannot race the write it is describing.
       */
      softDeleteManyReturningIds: async (ids, deletedAt, deletedBy) => {
        const live = await db
          .select({ id: authIdentities.id })
          .from(authIdentities)
          .where(and(inArray(authIdentities.id, [...ids]), isNull(authIdentities.deletedAt)))
        const hit = live.map((r) => r.id)
        if (hit.length === 0) return []
        // `isNull` again on the write, not just the read: a row soft-deleted
        // between the two would otherwise have its purge deadline pushed out to
        // this batch's, and the caller would be told it deleted a row it did
        // not. The re-read names the rows actually carrying this stamp.
        await db
          .update(authIdentities)
          .set({ deletedAt, deletedBy, emailVerified: false })
          .where(and(inArray(authIdentities.id, hit), isNull(authIdentities.deletedAt)))
        const stamped = await db
          .select({ id: authIdentities.id })
          .from(authIdentities)
          .where(and(inArray(authIdentities.id, hit), eq(authIdentities.deletedAt, deletedAt)))
        return stamped.map((r) => r.id)
      },

      eraseManyReturningIds: async (ids) => {
        const list = [...ids]
        const present = await db
          .select({ id: authIdentities.id })
          .from(authIdentities)
          .where(inArray(authIdentities.id, list))
        const hit = present.map((r) => r.id)
        if (hit.length === 0) return []
        // FK CASCADE handles these; explicit deletes are belt-and-suspenders,
        // as in the single-row `erase` above.
        await db.delete(authCredentials).where(inArray(authCredentials.identityId, hit))
        await db.delete(authSessions).where(inArray(authSessions.identityId, hit))
        await db.delete(authIdentities).where(inArray(authIdentities.id, hit))
        return hit
      },

      /**
       * The set-based form of `restore`, and it owes the caller the same two
       * refusals: a row whose grace window has closed is queued for purge, and a
       * row whose address a live identity now holds cannot come back without two
       * live rows answering to one email.
       *
       * Both are per-row decisions, so a row that fails one is left out of the
       * statement rather than throwing - `createSqlStores` reads an id missing
       * from the response as that row's soft failure, which is what keeps one
       * bad id in a batch of fifty from aborting the other forty-nine.
       */
      restoreManyReturning: async (ids) => {
        const list = [...ids]
        if (list.length === 0) return { candidates: [], restored: [] }
        const candidates = await db
          .select(identityColumns)
          .from(authIdentities)
          .where(inArray(authIdentities.id, list))
          .then((rows) => rows.map(reviveIdentityRow))
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
                inArray(sql`lower(${authIdentities.profile}->>'$.email')`, [...new Set(emails.values())]),
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
                    (claim) => sql`json_contains(${authIdentities.providers}, ${JSON.stringify(claim)})`,
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
        // Still-hidden rows only: a row restored by someone else between the
        // read and this write is not one this batch restored, and the re-read
        // below would otherwise claim it.
        await db
          .update(authIdentities)
          .set({ deletedAt: null, deletedBy: null })
          .where(and(inArray(authIdentities.id, okIds), isNotNull(authIdentities.deletedAt)))
        const restored = await db
          .select(identityColumns)
          .from(authIdentities)
          .where(and(inArray(authIdentities.id, okIds), isNull(authIdentities.deletedAt)))
          .then((rs) => rs.map(reviveIdentityRow))
        return { candidates, refused, restored }
      },

      /**
       * One conditional update per row, so each is matched on its OWN expected
       * version - a set-based form cannot express per-row version predicates
       * here without `UPDATE ... FROM (VALUES ...)`, which MySQL lacks. They run
       * back-to-back on one connection, so the batch is still atomic with the
       * caller's transaction; only the statement count fails to collapse.
       */
      updateProfileManyReturning: async (rows) => {
        const updated: string[] = []
        for (const r of rows) {
          const result = await db
            .update(authIdentities)
            .set(r.patch)
            .where(and(eq(authIdentities.id, r.id), eq(authIdentities.version, r.expectedVersion)))
          if (result[0].affectedRows > 0) updated.push(r.id)
        }
        if (updated.length === 0) return []
        return db
          .select(identityColumns)
          .from(authIdentities)
          .where(inArray(authIdentities.id, updated))
          .then((rs) => rs.map(reviveIdentityRow))
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
        if (survivorId === dupId) return reselectIdentity(survivorId)
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
        return reselectIdentity(survivorId)
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
              sql`${authCredentials.metadata}->>'$.provider' = ${provider}`,
              sql`${authCredentials.metadata}->>'$.sub' = ${sub}`,
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
        if (result[0].affectedRows === 0) return null
        return reselectCredential(id)
      },
      revoke: async (id, revokedAt, tenantId) => {
        const result = await db
          .update(authCredentials)
          .set({ revokedAt })
          .where(and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId)))
        if (result[0].affectedRows === 0) return null
        return reselectCredential(id)
      },
      delete: async (id, tenantId) => {
        // Read before the delete: after it there is nothing left to re-select,
        // and MySQL has no `RETURNING` to read on the way past.
        //
        // Through the SAME predicate the delete uses, not by id alone. Reading
        // by id handed another tenant's row straight back to a caller whose
        // delete could not touch it - the delete was correctly scoped, so the
        // row survived and the answer said it had not: a cross-tenant read
        // dressed up as a delete. Out of tenant is `null`, exactly as gone is.
        const where = and(eq(authCredentials.id, id), tenantWhere(authCredentials, tenantId))
        const rows = await db.select().from(authCredentials).where(where).limit(1)
        const row = rows[0]
        if (!row) return null
        await db.delete(authCredentials).where(where)
        return row
      },
      deleteByIdentitiesReturningIds: async (identityIds, tenantId) => {
        const where = and(inArray(authCredentials.identityId, [...identityIds]), tenantWhere(authCredentials, tenantId))
        const present = await db.select({ id: authCredentials.identityId }).from(authCredentials).where(where)
        const hit = present.map((r) => r.id).filter((id): id is string => id !== null)
        if (hit.length === 0) return []
        await db.delete(authCredentials).where(where)
        return hit
      },
      deleteByKind: async (identityId, kind, tenantId) => {
        const where = and(
          eq(authCredentials.identityId, identityId),
          eq(authCredentials.kind, kind),
          tenantWhere(authCredentials, tenantId),
        )
        // Same read-then-write as every other set-based MySQL statement here:
        // both run on one connection, so the read cannot race its own write.
        const doomed = await db.select().from(authCredentials).where(where)
        await db.delete(authCredentials).where(where)
        return doomed
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
        // A patch whose every key was an explicit `undefined` arrives here
        // empty, and drizzle refuses an `UPDATE` with nothing to set. "Change
        // none of these fields" is a read, not an error: the memory store hands
        // the row back untouched and so does this.
        if (Object.keys(patch).length === 0) return reselectSession(id)
        const result = await db.update(authSessions).set(patch).where(eq(authSessions.id, id))
        if (result[0].affectedRows === 0) return null
        return reselectSession(id)
      },
      delete: async (id) => {
        await db.delete(authSessions).where(eq(authSessions.id, id))
      },
      listByIdentity: async (identityId, tenantId) => {
        const rows = await db.select().from(authSessions).where(sessionScope(identityId, tenantId))
        return rows.map(reviveSessionRowRequired)
      },
      deleteAllForIdentity: async (identityId, tenantId) => {
        await db.delete(authSessions).where(sessionScope(identityId, tenantId))
      },
      deleteAllForIdentitiesReturningIds: async (identityIds) => {
        const list = [...identityIds]
        const present = await db
          .select({ id: authSessions.identityId })
          .from(authSessions)
          .where(inArray(authSessions.identityId, list))
        const hit = present.map((r) => r.id).filter((id): id is string => id !== null)
        if (hit.length === 0) return []
        await db.delete(authSessions).where(inArray(authSessions.identityId, hit))
        return hit
      },
      deleteManyReturningIds: async (ids) => {
        const list = [...ids]
        const present = await db
          .select({ id: authSessions.id })
          .from(authSessions)
          .where(inArray(authSessions.id, list))
        const hit = present.map((r) => r.id)
        if (hit.length === 0) return []
        await db.delete(authSessions).where(inArray(authSessions.id, hit))
        return hit
      },
      listByIdentities: (identityIds) =>
        db
          .select()
          .from(authSessions)
          .where(inArray(authSessions.identityId, [...identityIds]))
          .then((rows) => rows.map(reviveSessionRowRequired)),
      // Either clock, not just the outer one. `expiresAt` is the idle deadline a
      // session is renewed against and `absoluteExpiresAt` the ceiling it can
      // never pass; reading only the ceiling left every idled-out session in the
      // table until its absolute deadline, hours or days later.
      deleteExpired: async (now) => {
        const result = await db
          .delete(authSessions)
          .where(or(lt(authSessions.expiresAt, now), lt(authSessions.absoluteExpiresAt, now)))
        return result[0].affectedRows
      },
    },
    /**
     * Re-make this bridge against `client` - a drizzle transaction handle,
     * which is structurally the same database surface for every query builder
     * this bridge uses. The assertion is the boundary where an opaque client
     * re-enters the driver's own type, and belongs here rather than in `core/`
     * precisely because this file is the only one that knows the driver.
     */
    withClient: (client) => createDrizzleMysqlBridge<Profile, TSchema>(client as MySql2Database<TSchema>),
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
  return createSqlStores<Profile>(createDrizzleMysqlBridge<Profile>(db))
}
