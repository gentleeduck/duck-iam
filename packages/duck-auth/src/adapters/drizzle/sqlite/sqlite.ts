/** Drizzle (SQLite) against the three store contracts, method for method as pg reads them.
 *  Driver-agnostic: better-sqlite3, libsql/Turso or bun:sqlite. */

import { createRequire } from 'node:module'
import { and, desc, eq, gte, inArray, isNull, lt, or, type SQL, sql } from 'drizzle-orm'
import { alias, type BaseSQLiteDatabase, type SQLiteUpdateSetSource } from 'drizzle-orm/sqlite-core'
import { type Adapter, AdapterStore } from '~/adapters/adapter'
import { forProfile, inTenant, jsonMerged, rowWithLinks, stamped } from '~/adapters/drizzle/drizzle.rows'
import { actorId } from '~/core/actor'
import { authUuidV7 } from '~/core/crypto'
import { AuthError, type SqlFault, STORE_RAISES } from '~/core/errors'
import { toEmailList, withNormalisedEmail } from '~/core/identities/identities.constants'
import type { Identities } from '~/core/identities/identities.types'
import { stripUndefined } from '~/core/patch'
import { authCredentials, authIdentities, authIdentityProviders, authSessions } from './sqlite.schema'
import type { Sqlite } from './sqlite.types'

/** The one link a provider lookup is answering, joined under its own name so it can drive the plan. */
const lookupLink = alias(authIdentityProviders, 'lookup_link')

const linkFields = {
  addedAt: authIdentityProviders.addedAt,
  providerId: authIdentityProviders.providerId,
  providerSub: authIdentityProviders.providerSub,
}

/** Driver-agnostic handle, and the narrowing a transaction hands its callback. */
type Db<TSchema extends Record<string, unknown>> = BaseSQLiteDatabase<'sync' | 'async', unknown, TSchema>
type Writer = Pick<Sqlite.AnySqliteDatabase, 'select' | 'insert' | 'update' | 'delete'>

/** One class: the four facets share the handle, the `sqliteError` mapper and the `run` boundary that
 *  attaches `wrap`. Each is declared as its slot in `Adapter.Me`, so the contract states what it answers. */
export class DrizzleSqliteAdapter<
    TSchema extends Record<string, unknown> = Record<string, unknown>,
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  >
  extends AdapterStore<SqlFault>
  implements Adapter.Me<Profile>
{
  private readonly _db: Db<TSchema>

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
    void this._db.run(sql`pragma foreign_keys = on`)
  }

  /** WARN: a sync driver's `transaction` cannot wait on an async callback - better-sqlite3 refuses one,
   *  bun:sqlite commits early and never rolls back - so it is bracketed by hand on its single connection. */
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

  /** The links a row holds, read on their own: sqlite's json aggregates promise no order and answer raw integers. */
  private _links(id: string): Promise<Identities.ProviderLink[]> {
    return this._db
      .select(linkFields)
      .from(authIdentityProviders)
      .where(eq(authIdentityProviders.identityId, id))
      .orderBy(authIdentityProviders.addedAt)
  }

  /** The credential a caller named: a live row before a revoked one, then the newest of those. */
  private async _credential(match: SQL[], tenantId: string | undefined) {
    const [row] = await this._db
      .select()
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
      .returning()

    return row ?? null
  }

  /** A live row and its logins in one join. NOTE: inside a transaction, reached through `withClient(tx)` -
   *  `this._db` is a different connection, blind to what the transaction has written. */
  async find(by: Identities.By) {
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

    return rowWithLinks(
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
  }

  readonly identities = forProfile<Profile, SqlFault>({
    find: (by) => this.run(() => this.find(by)),

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
          if (providers.length === 0) return { ...created, providers: [] }

          // SECURITY: the unique on (provider_id, provider_sub) is what refuses a login another row already
          // holds. No check runs first, so there is no window between deciding and writing.
          const written = await tx
            .insert(authIdentityProviders)
            .values(providers.map((link) => ({ ...link, identityId: created.id })))
            .returning(linkFields)

          return { ...created, providers: written }
        }),
      ),

    erase: (id) =>
      this.run(async () => {
        // The cascade takes the links with the row, so they are read before it goes, not after.
        const providers = await this._links(id)
        const [row] = await this._db.delete(authIdentities).where(eq(authIdentities.id, id)).returning()

        return row ? { ...row, providers } : null
      }),

    /** The holder is the insert's own source row: one that is gone or hidden writes nothing and the read
     *  answers `null`, where asking first cost a round trip. */
    link: (identityId, link) =>
      this.run(async () => {
        // An insert's column list is the table's own order, so the select matches it position for position -
        // the id included, since a select has no column default to fall back on.
        const row = [
          sql.param(authUuidV7(), authIdentityProviders.id),
          authIdentities.id,
          sql.param(link.providerId, authIdentityProviders.providerId),
          sql.param(link.providerSub, authIdentityProviders.providerSub),
          sql.param(link.addedAt ?? new Date(), authIdentityProviders.addedAt),
        ]

        // SECURITY: (provider_id, provider_sub) refuses a login another identity holds; (identity_id,
        // provider_id) makes a repeat a no-op, so a caller racing a different sub is told, not given both.
        await this._db
          .insert(authIdentityProviders)
          .select(
            sql`select ${sql.join(row, sql`, `)} from ${authIdentities}
                where ${and(eq(authIdentities.id, identityId), isNull(authIdentities.deletedAt))}`,
          )
          .onConflictDoNothing({ target: [authIdentityProviders.identityId, authIdentityProviders.providerId] })

        return this.find({ id: identityId })
      }),

    /** One transaction: the dup's credentials, sessions and logins are re-pointed before it is deleted, since
     *  the FK cascade would take them with it, and a missing side rolls the whole thing back. */
    merge: (survivorId, dupId) =>
      this.run(async () => {
        if (survivorId === dupId) return this.find({ id: survivorId })

        return this._atomic(async (tx) => {
          // SECURITY: both sides are confirmed before anything moves. A merge that re-points the dup's rows
          // and only then finds the survivor gone has destroyed the dup for nothing.
          const present = await tx
            .select({ id: authIdentities.id })
            .from(authIdentities)
            .where(inArray(authIdentities.id, [survivorId, dupId]))
          if (present.length !== 2) return null

          // Two live passwords leave the row that answers a login up to the engine. Only a kind the
          // survivor already holds in the same tenant goes, matched in the delete rather than read out first.
          await tx.delete(authCredentials).where(
            and(
              eq(authCredentials.identityId, dupId),
              isNull(authCredentials.revokedAt),
              inArray(authCredentials.kind, ['password', 'totp']),
              // `is` rather than `=`: the tenants match when both are NULL, which a global row is.
              sql`exists (
                    select 1 from ${authCredentials} kept
                    where kept.identity_id = ${survivorId}
                      and kept.revoked_at is null
                      and kept.kind = ${authCredentials.kind}
                      and kept.tenant_id is ${authCredentials.tenantId}
                  )`,
            ),
          )

          await tx.update(authCredentials).set({ identityId: survivorId }).where(eq(authCredentials.identityId, dupId))
          await tx.update(authSessions).set({ identityId: survivorId }).where(eq(authSessions.identityId, dupId))

          // A provider both rows held would clash on the owned index, so the dup's copy stays put and the
          // delete below takes it with the row - one statement where clearing it first was two.
          await tx
            .update(authIdentityProviders)
            .set({ identityId: survivorId })
            .where(
              and(
                eq(authIdentityProviders.identityId, dupId),
                sql`not exists (
                    select 1 from ${authIdentityProviders} kept
                    where kept.identity_id = ${survivorId}
                      and kept.provider_id = ${authIdentityProviders.providerId}
                  )`,
              ),
            )

          await tx.delete(authIdentities).where(eq(authIdentities.id, dupId))

          return this.withClient(tx).find({ id: survivorId })
        })
      }),

    restore: (id) =>
      this.run(async () => {
        const [restored] = await this._db
          .update(authIdentities)
          .set({ deletedAt: null, deletedBy: null })
          .where(and(eq(authIdentities.id, id), gte(authIdentities.deletedAt, new Date())))
          .returning()
        if (restored) return { ...restored, providers: await this._links(id) }

        // Nothing matched: the row is not there, it is live already, or its window has closed - and only
        // this read sees a hidden row, which is the one thing `find` will not answer with.
        const [found] = await this._db
          .select({ deletedAt: authIdentities.deletedAt })
          .from(authIdentities)
          .where(eq(authIdentities.id, id))
          .limit(1)
        if (!found) return null
        if (found.deletedAt) throw new AuthError('AUTH_GRACE_EXPIRED')

        return this.find({ id })
      }),

    softDelete: (id, gracePeriodMs) =>
      this.run(async () => {
        // `deletedAt` is when the grace window closes, not when the delete happened.
        const [row] = await this._db
          .update(authIdentities)
          .set({ deletedAt: new Date(Date.now() + gracePeriodMs), deletedBy: actorId(), emailVerified: false })
          .where(and(eq(authIdentities.id, id), isNull(authIdentities.deletedAt)))
          .returning()

        return row ? { ...row, providers: await this._links(id) } : null
      }),

    unlink: (identityId, providerId) =>
      this.run(async () => {
        await this._db
          .delete(authIdentityProviders)
          .where(
            and(eq(authIdentityProviders.identityId, identityId), eq(authIdentityProviders.providerId, providerId)),
          )

        return this.find({ id: identityId })
      }),

    update: (id, patch, expectedVersion) =>
      this.run(async () => {
        const [row] = await this._db
          .update(authIdentities)
          // The row moves its own version on, so no caller can write a stale one or forget to bump it.
          .set({ ...stamped(withNormalisedEmail(patch)), version: sql`${authIdentities.version} + 1` })
          .where(and(eq(authIdentities.id, id), eq(authIdentities.version, expectedVersion)))
          .returning()
        if (!row) throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })

        return { ...row, providers: await this._links(id) }
      }),
  })

  readonly credentials: Adapter.Wrapped<Adapter.Me['credentials'], SqlFault> = {
    delete: (id, { tenantId }) =>
      this.run(async () => {
        const [row] = await this._db
          .delete(authCredentials)
          .where(and(eq(authCredentials.id, id), inTenant(authCredentials.tenantId, tenantId)))
          .returning()

        return row ?? null
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
          .returning(),
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
          .returning(),
      ),

    findByHashedSecret: (secretHash, kind, { tenantId }) =>
      this.run(() =>
        this._credential([eq(authCredentials.secret, secretHash), eq(authCredentials.kind, kind)], tenantId),
      ),

    findById: (id, { tenantId }) => this.run(() => this._credential([eq(authCredentials.id, id)], tenantId)),

    // NOTE: `provider`/`sub` live in free-form metadata, so the kind filter is what stops an api-key
    // answering an oauth lookup.
    findByProviderSub: (provider, sub, { tenantId }) =>
      this.run(() =>
        this._credential(
          [
            eq(authCredentials.kind, 'oauth'),
            sql`${authCredentials.metadata} ->> '$.provider' = ${provider}`,
            sql`${authCredentials.metadata} ->> '$.sub' = ${sub}`,
          ],
          tenantId,
        ),
      ),

    listByIdentity: (identityId, kind, { tenantId }) =>
      // Newest first, id breaking a same-millisecond tie: callers take the first live row, so an
      // unordered read left the engine to decide which password or totp answers.
      this.run(() =>
        this._db
          .select()
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

    /** One statement, merged under the row's own lock: `json_set` writes each key where it sits. Read-then-
     *  write needed a version to hold the two halves together and a retry for when it moved. */
    patchMetadata: (id, patch, { tenantId }) =>
      this.run(async () => {
        const metadata = jsonMerged(
          sql`coalesce(${authCredentials.metadata}, '{}')`,
          patch,
          (json) => sql`json(${json})`,
        )
        const written = await this._write({ expectedVersion: null, id, tenantId }, { metadata })
        if (!written) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return written
      }),

    revoke: (id, { tenantId }) =>
      this.run(() => this._write({ expectedVersion: null, id, tenantId }, { revokedAt: new Date() })),

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
          .set({ revokedAt: new Date(), updatedBy: actorId(), version: sql`${authCredentials.version} + 1` })
          .where(reach)
          .returning({ id: authCredentials.id })

        return moved.length
      }),

    /** NOTE: a rotation is a use, so it stamps lastUsedAt. */
    rotate: (id, secret, expectedVersion, { tenantId }) =>
      this.run(async () => {
        const row = await this._write({ expectedVersion, id, tenantId }, { lastUsedAt: new Date(), secret })
        if (row) return row

        throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })
      }),

    upsert: (input, ctx) =>
      this.run(async () => {
        const [created] = await this._db
          .insert(authCredentials)
          .values({
            ...input,
            createdBy: actorId(),
            tenantId: input.tenantId ?? ctx.tenantId ?? null,
            updatedBy: actorId(),
          })
          .returning()
        if (!created) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return created
      }),
  }

  readonly sessions: Adapter.Wrapped<Adapter.Me['sessions'], SqlFault> = {
    /** The row arrives whole - its id is the token hash the caller computed - so nothing here is stamped. */
    create: (session) =>
      this.run(async () => {
        await this._db.insert(authSessions).values(session)
      }),

    delete: (id) =>
      this.run(async () => {
        await this._db.delete(authSessions).where(eq(authSessions.id, id))
      }),

    deleteAllForIdentity: (identityId, ctx?) =>
      this.run(async () => {
        await this._db
          .delete(authSessions)
          .where(and(eq(authSessions.identityId, identityId), inTenant(authSessions.tenantId, ctx?.tenantId)))
      }),

    /** Either clock: `expiresAt` is the idle deadline, `absoluteExpiresAt` the ceiling it can never pass.
     *  NOTE: the ids come back rather than a row count, which better-sqlite3, libsql and bun each name differently. */
    gc: (now) =>
      this.run(async () => {
        const when = new Date(now)
        const gone = await this._db
          .delete(authSessions)
          .where(or(lt(authSessions.expiresAt, when), lt(authSessions.absoluteExpiresAt, when)))
          .returning({ id: authSessions.id })

        return { deleted: gone.length }
      }),

    getByHash: (id) =>
      this.run(async () => {
        const [row] = await this._db.select().from(authSessions).where(eq(authSessions.id, id)).limit(1)

        return row ?? null
      }),

    listByIdentity: (identityId, ctx?) =>
      this.run(() =>
        this._db
          .select()
          .from(authSessions)
          .where(and(eq(authSessions.identityId, identityId), inTenant(authSessions.tenantId, ctx?.tenantId))),
      ),

    update: (id, patch) =>
      this.run(async () => {
        // A patch with nothing to say is a no-op, not a failure: `{ csrfHash: maybeToken }` is how a caller
        // says "leave it alone", and `set({})` would reach the driver as a syntax error.
        const set = stripUndefined(patch)
        const [row] =
          Object.keys(set).length === 0
            ? await this._db.select().from(authSessions).where(eq(authSessions.id, id))
            : await this._db.update(authSessions).set(set).where(eq(authSessions.id, id)).returning()
        if (!row) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })

        return row
      }),
  }

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
