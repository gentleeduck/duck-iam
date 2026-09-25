/** Drizzle (SQLite) against the three store contracts, method for method as pg reads them.
 *  Driver-agnostic: better-sqlite3, libsql/Turso or bun:sqlite. */

import { createRequire } from 'node:module'
import { and, desc, eq, getTableColumns, gte, inArray, isNull, lt, or, type SQL, sql } from 'drizzle-orm'
import { alias, type BaseSQLiteDatabase, type SQLiteUpdateSetSource } from 'drizzle-orm/sqlite-core'
import { type Adapter, AdapterStore } from '~/adapters/adapter'
import { inTenant, jsonMerged, rowsWithLinks, rowWithLinks } from '~/adapters/drizzle/drizzle.rows'
import { actorId } from '~/core/actor'
import { authUuidV7 } from '~/core/crypto'
import { AuthError, type SqlFault, STORE_RAISES } from '~/core/errors'
import { toEmailList, withNormalisedEmail } from '~/core/identities/identities.constants'
import type { Identities } from '~/core/identities/identities.types'
import { stripUndefined } from '~/core/patch'
import { isFiniteNumber } from '~/core/predicates'
import { authCredentials, authIdentities, authIdentityProviders, authSessions, nowMs } from './sqlite.schema'
import type { Sqlite } from './sqlite.types'

/** The one link a provider lookup is answering, joined under its own name so it can drive the plan. */
const lookupLink = alias(authIdentityProviders, 'lookup_link')

const linkFields = {
  addedAt: authIdentityProviders.addedAt,
  addedBy: authIdentityProviders.addedBy,
  providerId: authIdentityProviders.providerId,
  providerSub: authIdentityProviders.providerSub,
}

/** Driver-agnostic handle, and the narrowing a transaction hands its callback. */
type Db<TSchema extends Record<string, unknown>> = BaseSQLiteDatabase<'sync' | 'async', unknown, TSchema>
type Writer = Pick<Db<Record<string, unknown>>, 'select' | 'insert' | 'update' | 'delete'>

/** The row contract: every column of each table, `updated_at` included. */
const credentialColumns = getTableColumns(authCredentials)
const sessionColumns = getTableColumns(authSessions)

/** One class: the four facets share the handle, the `STORE_RAISES` mapper and the `run` boundary that names
 *  what threw. Each is declared as its slot in `Adapter.Me`, so the contract states what it answers. */
export class DrizzleSqliteAdapter<
    TSchema extends Record<string, unknown> = Record<string, unknown>,
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  >
  extends AdapterStore<SqlFault>
  implements Adapter.Me<Profile>
{
  private readonly _db: Db<TSchema>
  /** The pragma below, held rather than dropped: a constructor cannot await, so every operation awaits it. */
  private readonly _foreignKeysOn: Promise<unknown>

  /** Over a file path, a driver `Database`, or a drizzle handle you already have. */
  constructor(input: string | Sqlite.SqliteClientLike | Db<TSchema>) {
    super(STORE_RAISES)
    const lazyRequire = createRequire(import.meta.url)
    const raw = typeof input === 'string' ? new (lazyRequire('better-sqlite3'))(input) : input
    // Straight at the driver, before drizzle wraps it, so a sync one has it on with nothing to await.
    if ('exec' in raw && typeof raw.exec === 'function') raw.exec('pragma foreign_keys = on')
    this._db = 'select' in raw ? raw : lazyRequire('drizzle-orm/better-sqlite3').drizzle(raw)
    // SECURITY: sqlite ignores every foreign key until this is on, per connection, so without it `erase`
    // leaves links behind whose unique keeps a login claimed by an identity that is gone.
    this._foreignKeysOn = Promise.resolve(this._db.run(sql`pragma foreign_keys = on`))
    // Silences the unhandled-rejection warning on a copy; `_foreignKeysOn` still rejects into `run`.
    void this._foreignKeysOn.catch(() => {})
  }

  /** Every facet calls through here, so an async driver cannot answer a query before the pragma has
   *  landed — fire-and-forget, the first writes of a freshly built adapter raced it with foreign keys
   *  still off. A pragma that failed rejects here rather than leaving the handle unenforced. */
  protected override async run<T>(call: () => Promise<T>): Promise<T> {
    return super.run(async () => {
      await this._foreignKeysOn
      return call()
    })
  }

  /** WARN: a sync driver's `transaction` cannot wait on an async callback: better-sqlite3 refuses one and
   *  bun:sqlite commits early without rolling back, so it is bracketed by hand on its single connection. */
  private async _atomic<T>(run: (tx: Writer) => Promise<T>): Promise<T> {
    if (Reflect.get(this._db, 'resultKind') !== 'sync') return this._db.transaction(run)

    await this._db.run(sql`begin immediate`)
    try {
      const out = await run(this._db)
      await this._db.run(sql`commit`)

      return out
    } catch (err) {
      await this._db.run(sql`rollback`)
      throw err
    }
  }

  /** The links a row holds, read on their own: sqlite's json aggregates promise no order and answer raw
   *  integers. Inside a transaction it takes that transaction's handle; the adapter's own is a different
   *  connection, blind to what the transaction has written. */
  private _links(id: string, db: Writer = this._db): Promise<Identities.ProviderLink[]> {
    return db
      .select(linkFields)
      .from(authIdentityProviders)
      .where(eq(authIdentityProviders.identityId, id))
      .orderBy(authIdentityProviders.addedAt)
  }

  /** {@link DrizzleSqliteAdapter._links} over a set, grouped by owner, for the writes that answer every row they touched. */
  private async _linksFor(ids: string[]): Promise<Map<string, Identities.ProviderLink[]>> {
    const rows = await this._db
      .select({ identityId: authIdentityProviders.identityId, link: linkFields })
      .from(authIdentityProviders)
      .where(inArray(authIdentityProviders.identityId, ids))
      .orderBy(authIdentityProviders.addedAt)

    const byId = new Map<string, Identities.ProviderLink[]>()
    for (const row of rows) {
      const links = byId.get(row.identityId)
      if (links) links.push(row.link)
      else byId.set(row.identityId, [row.link])
    }

    return byId
  }

  /** The credential a caller named: a live row before a revoked one, then the newest of those. */
  private async _credential(match: SQL[], tenantId: string | undefined) {
    const [row] = await this._db
      .select(credentialColumns)
      .from(authCredentials)
      .where(and(...match, inTenant(authCredentials.tenantId, tenantId)))
      .orderBy(sql`${authCredentials.revokedAt} is not null`, desc(authCredentials.createdAt))
      .limit(1)

    return row ?? null
  }

  /** A conditional write: `expectedVersion` null is unconditional, so a miss there is a missing row. */
  private async _write(
    { expectedVersion, id, tenantId }: { id: string; expectedVersion: number | null; tenantId: string | undefined },
    patch: SQLiteUpdateSetSource<typeof authCredentials>,
  ) {
    const [row] = await this._db
      .update(authCredentials)
      .set({ ...patch, version: sql`${authCredentials.version} + 1` })
      .where(
        and(
          eq(authCredentials.id, id),
          expectedVersion === null ? undefined : eq(authCredentials.version, expectedVersion),
          inTenant(authCredentials.tenantId, tenantId),
        ),
      )
      .returning(credentialColumns)

    return row ?? null
  }

  /** A live row and its logins in one join. */
  private async _find(by: { id: string } | { email: string } | { providerId: string; providerSub: string }) {
    let rows = this._db
      .select({ identity: authIdentities, link: linkFields })
      .from(authIdentities)
      .leftJoin(authIdentityProviders, eq(authIdentityProviders.identityId, authIdentities.id))
      .$dynamic()

    // PERF: the answering login joins under its own alias rather than a subquery in the where, so it walks
    // `uq_auth_identity_providers_sub` and takes the order from the index. 1.7x over 20k rows.
    if ('providerId' in by) {
      rows = rows.innerJoin(
        lookupLink,
        and(
          eq(lookupLink.identityId, authIdentities.id),
          eq(lookupLink.providerId, by.providerId),
          eq(lookupLink.providerSub, by.providerSub),
        ),
      )
    }

    const [row] = rowsWithLinks<Profile>(
      await rows
        .where(
          and(
            isNull(authIdentities.deletedAt),
            'id' in by ? eq(authIdentities.id, by.id) : undefined,
            'email' in by
              ? or(
                  ...toEmailList(by.email).map(
                    (e) => sql`lower(${authIdentities.profile} ->> '$.email') = lower(${e})`,
                  ),
                )
              : undefined,
          ),
        )
        .orderBy(authIdentityProviders.addedAt),
    )

    return row ?? null
  }

  readonly identities: Identities.Store<Profile> = {
    find: (by) =>
      this.run(async () => {
        const row = await this._find(by)
        if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

        return row
      }),

    /** NOTE: `atomic`, not a bare `transaction`, see the note on it. The rest need no transaction at all:
     *  they write one table and then read another the write never touched. */
    create: (input) =>
      this.run(() =>
        this._atomic(async (tx) => {
          const { providers, ...columns } = withNormalisedEmail(input)
          const [created] = await tx
            .insert(authIdentities)
            .values({ ...columns, createdBy: actorId(), deletedAt: null, deletedBy: null, updatedBy: actorId() })
            .returning()
          if (!created) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')
          if (providers.length === 0) return rowWithLinks<Profile>(created)

          // SECURITY: the unique on (provider_id, provider_sub) is what refuses a login another row already
          // holds. No check runs first, so there is no window between deciding and writing.
          const written = await tx
            .insert(authIdentityProviders)
            .values(providers.map((link) => ({ ...link, addedBy: actorId(), identityId: created.id })))
            .returning(linkFields)

          return rowWithLinks<Profile>(created, written)
        }),
      ),

    erase: (id) =>
      this.run(async () => {
        // The cascade takes the links with the row, so they are read before it goes, not after.
        const providers = await this._links(id)
        const [row] = await this._db.delete(authIdentities).where(eq(authIdentities.id, id)).returning()
        if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

        return rowWithLinks<Profile>(row, providers)
      }),

    /** {@link DrizzleSqliteAdapter.erase} over the set: an id with no row is simply absent from the answer, which is the only
     *  thing one statement can say about a miss. */
    eraseMany: (ids) =>
      this.run(async () => {
        const links = await this._linksFor(ids)
        const gone = await this._db.delete(authIdentities).where(inArray(authIdentities.id, ids)).returning()

        return gone.map((row) => rowWithLinks<Profile>(row, links.get(row.id) ?? []))
      }),

    /** What makes a soft delete a delete: a window that has closed is past restoring, so the row goes for
     *  real. `lt` never matches a NULL, so a live row is not reachable from here. */
    gc: (now) =>
      this.run(async () => {
        // The cutoff is the caller's, and every comparison against NaN is false while every one against
        // Infinity is true, so an unusable number does not fail - it sweeps nothing or it sweeps everything,
        // and the dialects disagreed about which.
        if (!isFiniteNumber(now)) {
          throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'gc(now) requires a finite epoch-ms cutoff' })
        }
        const gone = await this._db
          .delete(authIdentities)
          .where(lt(authIdentities.deletedAt, new Date(now)))
          .returning({ id: authIdentities.id })

        return { deleted: gone.length }
      }),

    /** The holder is the insert's own source row, so one that is gone or hidden writes nothing and the
     *  read that follows raises.
     *  SECURITY: one transaction. Both statements gate on a live row, and a `softDelete` landing between
     *  them otherwise leaves the link written while the bump matches nothing, so the caller is told the
     *  link failed while the sub stays claimed by a hidden row no other identity can take it from. */
    link: (identityId, link) =>
      this.run(() =>
        this._atomic(async (tx) => {
          // An insert's column list is the table's own order, so the select matches it position for
          // position, the id included, since a select has no column default to fall back on.
          const row = [
            sql.param(authUuidV7(), authIdentityProviders.id),
            authIdentities.id,
            sql.param(link.providerId, authIdentityProviders.providerId),
            sql.param(link.providerSub, authIdentityProviders.providerSub),
            sql.param(link.addedAt ?? new Date(), authIdentityProviders.addedAt),
            sql.param(actorId(), authIdentityProviders.addedBy),
          ]

          // SECURITY: (provider_id, provider_sub) refuses a login another identity holds; (identity_id,
          // provider_id) makes a repeat a no-op, so a caller racing a different sub is told, not given both.
          await tx
            .insert(authIdentityProviders)
            .select(
              sql`select ${sql.join(row, sql`, `)} from ${authIdentities}
                  where ${and(eq(authIdentities.id, identityId), isNull(authIdentities.deletedAt))}`,
            )
            .onConflictDoNothing({ target: [authIdentityProviders.identityId, authIdentityProviders.providerId] })

          // A login is part of what a read of the identity answers, so its version moves with one. The bump
          // returns the row it wrote, which is the answer; re-reading it would be a third statement.
          const [linked] = await tx
            .update(authIdentities)
            .set({ version: sql`${authIdentities.version} + 1` })
            .where(and(eq(authIdentities.id, identityId), isNull(authIdentities.deletedAt)))
            .returning()
          if (!linked) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return rowWithLinks<Profile>(linked, await this._links(identityId, tx))
        }),
      ),

    restore: (id) =>
      this.run(async () => {
        const [restored] = await this._db
          .update(authIdentities)
          .set({ deletedAt: null, deletedBy: null, version: sql`${authIdentities.version} + 1` })
          .where(and(eq(authIdentities.id, id), gte(authIdentities.deletedAt, new Date())))
          .returning()
        if (restored) return rowWithLinks<Profile>(restored, await this._links(id))

        // Nothing matched: the row is not there, it is live already, or its window has closed, and only
        // this read sees a hidden row, which is the one thing `find` will not answer with.
        const [found] = await this._db
          .select({ deletedAt: authIdentities.deletedAt })
          .from(authIdentities)
          .where(eq(authIdentities.id, id))
          .limit(1)
        if (!found) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')
        if (found.deletedAt) throw new AuthError('AUTH_GRACE_EXPIRED')

        const row = await this._find({ id })
        if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

        return row
      }),

    /** The set form over one id. It answers with the rows it hid, so an empty answer is the miss this
     *  raises on. */
    softDelete: (id, gracePeriodMs) =>
      this.run(async () => {
        const [row] = await this.identities.softDeleteMany([id], gracePeriodMs)
        if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

        return row
      }),

    /** `deletedAt` is when the grace window closes, not when the delete happened.
     *  `isNull(deletedAt)` keeps an already-hidden row out of the answer, so re-hiding it reads as a miss
     *  rather than moving its window. */
    softDeleteMany: (ids, gracePeriodMs) =>
      this.run(async () => {
        const hidden = await this._db
          .update(authIdentities)
          .set({
            deletedAt: new Date(Date.now() + gracePeriodMs),
            deletedBy: actorId(),
            emailVerified: false,
            version: sql`${authIdentities.version} + 1`,
          })
          .where(and(inArray(authIdentities.id, ids), isNull(authIdentities.deletedAt)))
          .returning()
        const links = await this._linksFor(hidden.map((row) => row.id))

        return hidden.map((row) => rowWithLinks<Profile>(row, links.get(row.id) ?? []))
      }),

    /** SECURITY: one transaction. The delete lands before the gated bump, so a `softDelete` arriving between
     *  them otherwise leaves the login detached while the caller is told the unlink failed. */
    unlink: (identityId, providerId) =>
      this.run(() =>
        this._atomic(async (tx) => {
          await tx
            .delete(authIdentityProviders)
            .where(
              and(eq(authIdentityProviders.identityId, identityId), eq(authIdentityProviders.providerId, providerId)),
            )

          const [row] = await tx
            .update(authIdentities)
            .set({ version: sql`${authIdentities.version} + 1` })
            .where(and(eq(authIdentities.id, identityId), isNull(authIdentities.deletedAt)))
            .returning()
          if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return rowWithLinks<Profile>(row, await this._links(identityId, tx))
        }),
      ),

    update: (id, patch, expectedVersion) =>
      this.run(async () => {
        const [row] = await this._db
          .update(authIdentities)
          // The row moves its own version on, so no caller can write a stale one or forget to bump it.
          .set({
            ...stripUndefined(withNormalisedEmail(patch)),
            updatedBy: actorId(),
            version: sql`${authIdentities.version} + 1`,
          })
          .where(
            and(
              eq(authIdentities.id, id),
              eq(authIdentities.version, expectedVersion),
              isNull(authIdentities.deletedAt),
            ),
          )
          .returning()
        if (!row) throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })

        return rowWithLinks<Profile>(row, await this._links(id))
      }),
  }

  readonly credentials: Adapter.Me['credentials'] = {
    delete: (id, { tenantId }) =>
      this.run(async () => {
        const [row] = await this._db
          .delete(authCredentials)
          .where(and(eq(authCredentials.id, id), inTenant(authCredentials.tenantId, tenantId)))
          .returning(credentialColumns)
        if (!row) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return row
      }),

    deleteByKind: (identityId, kind, { tenantId }) =>
      this.run(() =>
        this._db
          .delete(authCredentials)
          .where(
            and(
              eq(authCredentials.identityId, identityId),
              eq(authCredentials.kind, kind),
              inTenant(authCredentials.tenantId, tenantId),
            ),
          )
          .returning(credentialColumns),
      ),

    deleteByKindAndPurpose: (identityId, kind, purpose, { tenantId }) =>
      this.run(() =>
        this._db
          .delete(authCredentials)
          .where(
            and(
              eq(authCredentials.identityId, identityId),
              eq(authCredentials.kind, kind),
              sql`${authCredentials.metadata} ->> '$.purpose' = ${purpose}`,
              inTenant(authCredentials.tenantId, tenantId),
            ),
          )
          .returning(credentialColumns),
      ),

    findByHashedSecret: (secretHash, kind, { tenantId }) =>
      this.run(async () => {
        const row = await this._credential(
          [eq(authCredentials.secret, secretHash), eq(authCredentials.kind, kind)],
          tenantId,
        )
        if (!row) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return row
      }),

    findById: (id, { tenantId }) =>
      this.run(async () => {
        const row = await this._credential([eq(authCredentials.id, id)], tenantId)
        if (!row) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return row
      }),

    listByIdentity: (identityId, kind, { tenantId }) =>
      // Newest first, id breaking a same-millisecond tie: callers take the first live row.
      this.run(() =>
        this._db
          .select(credentialColumns)
          .from(authCredentials)
          .where(
            and(
              eq(authCredentials.identityId, identityId),
              kind === null ? undefined : eq(authCredentials.kind, kind),
              inTenant(authCredentials.tenantId, tenantId),
            ),
          )
          .orderBy(desc(authCredentials.createdAt), desc(authCredentials.id)),
      ),

    /** One statement, merged under the row's own lock: `json_set` writes each key where it sits. */
    patchMetadata: (id, patch, { tenantId }, expectedVersion) =>
      this.run(async () => {
        const metadata = jsonMerged(
          sql`coalesce(${authCredentials.metadata}, '{}')`,
          patch,
          (json) => sql`json(${json})`,
        )
        const written = await this._write({ expectedVersion: expectedVersion ?? null, id, tenantId }, { metadata })
        if (!written) {
          // A conditional write matches no row whether it is gone, another tenant's, or a version behind,
          // so a caller that asked for a version is told the one thing it can act on.
          if (expectedVersion !== undefined) {
            throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })
          }
          throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
        }

        return written
      }),

    revoke: (id, { tenantId }) =>
      this.run(async () => {
        // The DB's own clock, not the app's: `created_at` is `nowMs`-stamped by sqlite, and an app-clock
        // `revokedAt` can land behind it on a fast create-then-revoke, tripping
        // chk_auth_credentials_revoked_after_created on a perfectly legitimate write.
        const row = await this._write({ expectedVersion: null, id, tenantId }, { revokedAt: nowMs })
        if (!row) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return row
      }),

    /** The familyId is read out of `metadata`, which is where every oauth row carries it. */
    revokeFamily: (familyId, { tenantId }) =>
      this.run(async () => {
        const reach = and(
          eq(authCredentials.kind, 'oauth'),
          isNull(authCredentials.revokedAt),
          sql`${authCredentials.metadata} ->> '$.familyId' = ${familyId}`,
          inTenant(authCredentials.tenantId, tenantId),
        )
        const moved = await this._db
          .update(authCredentials)
          .set({ revokedAt: nowMs, updatedBy: actorId(), version: sql`${authCredentials.version} + 1` })
          .where(reach)
          .returning({ id: authCredentials.id })

        return moved.length
      }),

    /** NOTE: a rotation is a use, so it stamps lastUsedAt. */
    rotate: (id, secret, expectedVersion, { tenantId }) =>
      this.run(async () => {
        const row = await this._write({ expectedVersion, id, tenantId }, { lastUsedAt: nowMs, secret })
        if (row) return row

        throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })
      }),

    create: (input, ctx) =>
      this.run(async () => {
        const [created] = await this._db
          .insert(authCredentials)
          .values({
            ...input,
            createdBy: actorId(),
            tenantId: input.tenantId ?? ctx.tenantId ?? null,
            updatedBy: actorId(),
          })
          .returning(credentialColumns)
        if (!created) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return created
      }),
  }

  readonly sessions: Adapter.Me['sessions'] = {
    /** The row arrives whole, its id being the token hash the caller computed, so nothing here is stamped. */
    create: (session) =>
      this.run(async () => {
        await this._db.insert(authSessions).values(session)
      }),

    delete: (id) =>
      this.run(async () => {
        await this._db.delete(authSessions).where(eq(authSessions.id, id))
      }),

    /** One statement for the whole set. `RETURNING` hands back the rows it removed, which both names a
     *  miss and names what went, so nothing has to read them before the delete. */
    deleteAllForIdentities: (identityIds) =>
      this.run(() =>
        this._db
          .delete(authSessions)
          .where(inArray(authSessions.identityId, identityIds))
          .returning({ id: authSessions.id, identityId: authSessions.identityId }),
      ),

    deleteAllForIdentity: (identityId, ctx?) =>
      this.run(async () => {
        await this._db
          .delete(authSessions)
          .where(and(eq(authSessions.identityId, identityId), inTenant(authSessions.tenantId, ctx?.tenantId)))
      }),

    deleteMany: (ids) =>
      this.run(() =>
        this._db
          .delete(authSessions)
          .where(inArray(authSessions.id, ids))
          .returning({ id: authSessions.id, identityId: authSessions.identityId }),
      ),

    /** Either clock: `expiresAt` is the idle deadline, `absoluteExpiresAt` the ceiling it can never pass.
     *  NOTE: the ids come back rather than a row count, which better-sqlite3, libsql and bun each name differently. */
    gc: (now) =>
      this.run(async () => {
        // The cutoff is the caller's, and every comparison against NaN is false while every one against
        // Infinity is true, so an unusable number does not fail - it sweeps nothing or it sweeps everything,
        // and the dialects disagreed about which.
        if (!isFiniteNumber(now)) {
          throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'gc(now) requires a finite epoch-ms cutoff' })
        }
        const when = new Date(now)
        const gone = await this._db
          .delete(authSessions)
          .where(or(lt(authSessions.expiresAt, when), lt(authSessions.absoluteExpiresAt, when)))
          .returning({ id: authSessions.id })

        return { deleted: gone.length }
      }),

    getByHash: (id) =>
      this.run(async () => {
        const [row] = await this._db.select(sessionColumns).from(authSessions).where(eq(authSessions.id, id)).limit(1)
        if (!row) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })

        return row
      }),

    listByIdentity: (identityId, ctx?) =>
      this.run(() =>
        this._db
          .select(sessionColumns)
          .from(authSessions)
          .where(and(eq(authSessions.identityId, identityId), inTenant(authSessions.tenantId, ctx?.tenantId))),
      ),

    update: (id, patch, expectedUpdatedAt) =>
      this.run(async () => {
        // A patch with nothing to say is a no-op, not a failure: `{ csrfHash: maybeToken }` is how a caller
        // says "leave it alone", and `set({})` would reach the driver as a syntax error.
        // `id` is the sid hash the caller's cookie carries: a patch naming it is dropped, never a move.
        const { id: _pinnedId, ...movable } = patch
        const set = stripUndefined(movable)
        // `$onUpdate` stamps `new Date()`, which is the same value for two writes inside one millisecond -
        // and a guard comparing equal to a read taken before the first of them then lands on top of it. The
        // database computes the next value instead, so the token is strictly increasing however the two
        // writers interleave and whether or not either passed a guard.
        const writeSet = { ...set, updatedAt: sql`max(${authSessions.updatedAt} + 1, ${Date.now()})` }
        // The guard rides in the WHERE so the database enforces it, and is read once first so a refusal can
        // name which of the two things went wrong: AUTH_SESSION_REVOKED is in the reader's absent set, so
        // answering it for a lost race would let `orNull()` read the refusal back as "no session".
        const guard = expectedUpdatedAt === undefined ? undefined : eq(authSessions.updatedAt, expectedUpdatedAt)
        if (expectedUpdatedAt !== undefined) {
          const [cur] = await this._db
            .select({ updatedAt: authSessions.updatedAt })
            .from(authSessions)
            .where(eq(authSessions.id, id))
            .limit(1)
          if (!cur) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })
          if (cur.updatedAt.getTime() !== expectedUpdatedAt.getTime()) {
            throw new AuthError('AUTH_STALE_WRITE', {
              actual: cur.updatedAt.getTime(),
              expected: expectedUpdatedAt.getTime(),
            })
          }
        }
        const [row] =
          Object.keys(set).length === 0
            ? await this._db
                .select(sessionColumns)
                .from(authSessions)
                .where(and(eq(authSessions.id, id), guard))
            : await this._db
                .update(authSessions)
                .set(writeSet)
                .where(and(eq(authSessions.id, id), guard))
                .returning(sessionColumns)
        if (!row) {
          // The pre-read agreed and the write still matched nothing, so a racer moved `updatedAt` between them.
          if (expectedUpdatedAt !== undefined) {
            throw new AuthError('AUTH_STALE_WRITE', { expected: expectedUpdatedAt.getTime() })
          }
          throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })
        }

        return row
      }),
  }

  /** Rebinds all four stores onto a transaction handle, so one unit of work shares it. */
  withClient(client: unknown): DrizzleSqliteAdapter<TSchema, Profile> {
    // A handle is `db` or the `tx` a transaction hands its callback, and both answer all three.
    const isHandle = (c: unknown): c is Db<TSchema> =>
      typeof c === 'object' && c !== null && 'select' in c && 'insert' in c && 'transaction' in c
    if (!isHandle(client)) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'withClient expects a drizzle sqlite handle' })
    }

    return new DrizzleSqliteAdapter(client)
  }
}

/** Constructs a {@link DrizzleSqliteAdapter}. */
export function drizzleSqliteAdapter<
  TSchema extends Record<string, unknown> = Record<string, unknown>,
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(input: string | Sqlite.SqliteClientLike | Db<TSchema>): DrizzleSqliteAdapter<TSchema, Profile> {
  return new DrizzleSqliteAdapter<TSchema, Profile>(input)
}
