/** Drizzle (MySQL / MariaDB) against the three store contracts, method for method as pg reads them.
 *  WARN: no `RETURNING`, and `affectedRows` cannot tell a miss from a no-op, so a guarded write takes a lock. */

import { createRequire } from 'node:module'
import { and, desc, eq, getTableColumns, gte, inArray, isNull, lt, or, type SQL, sql } from 'drizzle-orm'
import { alias, type MySqlUpdateSetSource } from 'drizzle-orm/mysql-core'
import type { MySql2Database } from 'drizzle-orm/mysql2'
import { type Adapter, AdapterStore } from '~/adapters/adapter'
import { forProfile, inTenant, jsonMerged, rowWithLinks, stamped } from '~/adapters/drizzle/drizzle.rows'
import { actorId } from '~/core/actor'
import { authUuidV7 } from '~/core/crypto'
import { AuthError, type SqlFault, STORE_RAISES } from '~/core/errors'
import { toEmailList, withNormalisedEmail } from '~/core/identities/identities.constants'
import type { Identities } from '~/core/identities/identities.types'
import { stripUndefined } from '~/core/patch'
import { authCredentials, authIdentities, authIdentityProviders, authSessions } from './mysql.schema'
import type { Mysql } from './mysql.types'

/** The one link a provider lookup is answering, joined under its own name so it can drive the plan. */
const lookupLink = alias(authIdentityProviders, 'lookup_link')

const linkFields = {
  addedAt: authIdentityProviders.addedAt,
  providerId: authIdentityProviders.providerId,
  providerSub: authIdentityProviders.providerSub,
}

/** What a read needs of a handle: `db` itself, or the `tx` a transaction hands its callback. */
type Reader = Pick<Mysql.AnyMySql2Database, 'select'>

/** The row contract: each table minus its generated columns, which are index carriers and not fields. */
const { emailNorm: _emailNorm, usernameNorm: _usernameNorm, ...identityColumns } = getTableColumns(authIdentities)
const { oauthProvider: _oauthProvider, oauthSub: _oauthSub, ...credentialColumns } = getTableColumns(authCredentials)

/** MySQL has no `RETURNING`, so a write holds its row under a lock and re-reads it after. */
function lockRow(tx: Reader, id: string) {
  return tx
    .select({ id: authIdentities.id })
    .from(authIdentities)
    .where(eq(authIdentities.id, id))
    .limit(1)
    .for('update')
}

/** One class: the four facets share the handle, the `mysqlError` mapper and the `run` boundary that
 *  attaches `wrap`. Each is declared as its slot in `Adapter.Me`, so the contract states what it answers. */
export class DrizzleMysqlAdapter<
    TSchema extends Record<string, unknown> = Record<string, unknown>,
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  >
  extends AdapterStore<SqlFault>
  implements Adapter.Me<Profile>
{
  private readonly _db: MySql2Database<TSchema>

  /** Over a connection string, a `mysql2` pool, or a drizzle handle you already have. */
  constructor(input: string | Mysql.MySql2PoolLike | MySql2Database<TSchema>) {
    super(STORE_RAISES)
    const lazyRequire = createRequire(import.meta.url)
    this._db =
      typeof input === 'string'
        ? lazyRequire('drizzle-orm/mysql2').drizzle(lazyRequire('mysql2/promise').createPool(input))
        : 'select' in input
          ? input
          : lazyRequire('drizzle-orm/mysql2').drizzle(input)
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

  /** No `RETURNING`, so the rows are read under their own lock before the delete takes them. */
  private _erase(reach: SQL | undefined) {
    return this._db.transaction(async (tx) => {
      const going = await tx.select(credentialColumns).from(authCredentials).where(reach).for('update')
      if (going.length > 0) await tx.delete(authCredentials).where(reach)

      return going
    })
  }

  /** A conditional write: `expectedVersion` null is unconditional, so a miss there is a missing row. */
  private _write(
    { expectedVersion, id, tenantId }: { id: string; expectedVersion: number | null; tenantId: string | undefined },
    patch: MySqlUpdateSetSource<typeof authCredentials>,
  ) {
    const reach = and(
      eq(authCredentials.id, id),
      expectedVersion === null ? undefined : eq(authCredentials.version, expectedVersion),
      inTenant(authCredentials.tenantId, tenantId),
    )

    return this._db.transaction(async (tx) => {
      // The update takes the row lock a locked read took, and its own count answers what that read did.
      // A miss cannot tell a missing id from a moved version, so the caller decides.
      const [written] = await tx
        .update(authCredentials)
        .set({ ...patch, version: sql`${authCredentials.version} + 1` })
        .where(reach)
      if (written.affectedRows === 0) return null

      const [row] = await tx.select(credentialColumns).from(authCredentials).where(eq(authCredentials.id, id)).limit(1)

      return row ?? null
    })
  }

  /** A live row and its logins in one join; `hidden` is for a write reading back a row it just hid.
   *  NOTE: inside a transaction, reached through `withClient(tx)` - `this._db` is a blind connection. */
  async find(by: Identities.By, hidden = false) {
    let rows = this._db
      .select({ identity: identityColumns, link: linkFields })
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
            hidden ? undefined : isNull(authIdentities.deletedAt),
            'id' in by ? eq(authIdentities.id, by.id) : undefined,
            // PERF: the stored column, not the expression behind it - MySQL will not match a functional
            // index when the comparison carries the connection's collation. 24ms against 0.4ms over 50k.
            'email' in by
              ? or(...toEmailList(by.email).map((e) => eq(authIdentities.emailNorm, sql`lower(${e})`)))
              : undefined,
          ),
        )
        .orderBy(authIdentityProviders.addedAt),
    )
  }

  readonly identities = forProfile<Profile, SqlFault>({
    find: (by) => this.run(() => this.find(by)),

    create: (input) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          const { providers, ...columns } = withNormalisedEmail(input)
          // The id is the table's own `$defaultFn`, minted here so the links and the re-read have one to name.
          const id = authUuidV7()
          await tx
            .insert(authIdentities)
            .values({ ...columns, createdBy: actorId(), deletedAt: null, deletedBy: null, id, updatedBy: actorId() })

          // SECURITY: the unique on (provider_id, provider_sub) is what refuses a login another row already
          // holds. No check runs first, so there is no window between deciding and writing.
          if (providers.length > 0) {
            await tx.insert(authIdentityProviders).values(providers.map((link) => ({ ...link, identityId: id })))
          }

          const created = await this.withClient(tx).find({ id })
          if (!created) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return created
        }),
      ),

    erase: (id) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          const [locked] = await lockRow(tx, id)
          if (!locked) return null

          // The cascade takes the links with the row, so it is read whole while they are still there.
          const found = await this.withClient(tx).find({ id }, true)
          await tx.delete(authIdentities).where(eq(authIdentities.id, id))

          return found
        }),
      ),

    /** One write, no transaction: the holder is the insert's own source row, so one that is gone or hidden
     *  writes nothing and the read answers `null`, and the repeat is settled in the same where. */
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

        // SECURITY: (provider_id, provider_sub) refuses a login another identity holds. `on duplicate key
        // update` cannot be aimed at one index - it would swallow the stolen sub - so the owned index is read.
        await this._db.insert(authIdentityProviders).select(
          sql`select ${sql.join(row, sql`, `)} from ${authIdentities}
              where ${and(eq(authIdentities.id, identityId), isNull(authIdentities.deletedAt))}
                and not exists (
                  select 1 from (
                    select held.id from ${authIdentityProviders} held
                    where held.identity_id = ${identityId}
                      and held.provider_id = ${sql.param(link.providerId, authIdentityProviders.providerId)}
                  ) owned
                )`,
        )

        return this.find({ id: identityId })
      }),

    /** One transaction: the dup's credentials, sessions and logins are re-pointed before it is deleted, since
     *  the FK cascade would take them with it, and a missing side rolls the whole thing back. */
    merge: (survivorId, dupId) =>
      this.run(async () => {
        if (survivorId === dupId) return this.find({ id: survivorId })

        return this._db.transaction(async (tx) => {
          // SECURITY: both sides are confirmed before anything moves. A merge that re-points the dup's rows
          // and only then finds the survivor gone has destroyed the dup for nothing.
          const present = await tx
            .select({ id: authIdentities.id })
            .from(authIdentities)
            .where(inArray(authIdentities.id, [survivorId, dupId]))
            .for('update')
          if (present.length !== 2) return null

          // Two live passwords leave the row that answers a login up to the engine. Only a kind the
          // survivor already holds in the same tenant goes, matched in the delete rather than read out first.
          await tx.delete(authCredentials).where(
            and(
              eq(authCredentials.identityId, dupId),
              isNull(authCredentials.revokedAt),
              inArray(authCredentials.kind, ['password', 'totp']),
              // NOTE: through a derived table, which MySQL requires of a query naming its own delete
              // target, and `<=>` so two global (NULL) tenants count as the same tenant.
              sql`exists (
                    select 1 from (
                      select kept.kind, kept.tenant_id from ${authCredentials} kept
                      where kept.identity_id = ${survivorId} and kept.revoked_at is null
                    ) survivor
                    where survivor.kind = ${authCredentials.kind}
                      and survivor.tenant_id <=> ${authCredentials.tenantId}
                  )`,
            ),
          )

          await tx.update(authCredentials).set({ identityId: survivorId }).where(eq(authCredentials.identityId, dupId))
          await tx.update(authSessions).set({ identityId: survivorId }).where(eq(authSessions.identityId, dupId))

          // A login both rows held would clash on the owned index, so the dup's copy stays put and the
          // delete below takes it with the row - one statement where clearing it first was two.
          await tx
            .update(authIdentityProviders)
            .set({ identityId: survivorId })
            .where(
              and(
                eq(authIdentityProviders.identityId, dupId),
                // NOTE: through a derived table, which MySQL requires of a query naming its own update target.
                sql`not exists (
                    select 1 from (
                      select kept.provider_id from ${authIdentityProviders} kept
                      where kept.identity_id = ${survivorId}
                    ) survivor
                    where survivor.provider_id = ${authIdentityProviders.providerId}
                  )`,
              ),
            )

          await tx.delete(authIdentities).where(eq(authIdentities.id, dupId))

          return this.withClient(tx).find({ id: survivorId })
        })
      }),

    restore: (id) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          // No locked read first: this one answers the same question, and the write below is conditional
          // on the window still being open either way.
          const found = await this.withClient(tx).find({ id }, true)
          if (!found) return null
          if (!found.deletedAt) return found

          await tx
            .update(authIdentities)
            .set({ deletedAt: null, deletedBy: null })
            .where(and(eq(authIdentities.id, id), gte(authIdentities.deletedAt, new Date())))

          // The re-read, not the driver's row count, is what says whether the window was still open.
          const after = await this.withClient(tx).find({ id }, true)
          if (after?.deletedAt) throw new AuthError('AUTH_GRACE_EXPIRED')

          return after
        }),
      ),

    softDelete: (id, gracePeriodMs) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          const reach = and(eq(authIdentities.id, id), isNull(authIdentities.deletedAt))

          // `deletedAt` is when the grace window closes, not when the delete happened. The update takes the
          // row lock a locked read took, and its own count says whether it found a live row.
          const [hidden] = await tx
            .update(authIdentities)
            .set({ deletedAt: new Date(Date.now() + gracePeriodMs), deletedBy: actorId(), emailVerified: false })
            .where(reach)
          if (hidden.affectedRows === 0) return null

          return this.withClient(tx).find({ id }, true)
        }),
      ),

    unlink: (identityId, providerId) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          await tx
            .delete(authIdentityProviders)
            .where(
              and(eq(authIdentityProviders.identityId, identityId), eq(authIdentityProviders.providerId, providerId)),
            )

          return this.withClient(tx).find({ id: identityId })
        }),
      ),

    update: (id, patch, expectedVersion) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          const reach = and(eq(authIdentities.id, id), eq(authIdentities.version, expectedVersion))
          // NOTE: it cannot name the version it found, but pg's conditional write cannot either, and one
          // answer across every dialect is worth more than the extra field.
          const [written] = await tx
            .update(authIdentities)
            // The row moves its own version on, so no caller can write a stale one or forget to bump it.
            .set({ ...stamped(withNormalisedEmail(patch)), version: sql`${authIdentities.version} + 1` })
            .where(reach)
          if (written.affectedRows === 0)
            throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })

          const row = await this.withClient(tx).find({ id })
          if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return row
        }),
      ),
  })

  readonly credentials: Adapter.Wrapped<Adapter.Me['credentials'], SqlFault> = {
    delete: (id, { tenantId }) =>
      this.run(async () => {
        const [row] = await this._erase(and(eq(authCredentials.id, id), inTenant(authCredentials.tenantId, tenantId)))

        return row ?? null
      }),

    deleteByKind: (identityId, kind, { tenantId }) =>
      this.run(() =>
        this._erase(
          and(
            eq(authCredentials.identityId, identityId),
            eq(authCredentials.kind, kind),
            inTenant(authCredentials.tenantId, tenantId),
          ),
        ),
      ),

    deleteByKindAndPurpose: (identityId, kind, purpose, { tenantId }) =>
      this.run(() =>
        this._erase(
          and(
            eq(authCredentials.identityId, identityId),
            eq(authCredentials.kind, kind),
            sql`${authCredentials.metadata} ->> '$.purpose' = ${purpose}`,
            inTenant(authCredentials.tenantId, tenantId),
          ),
        ),
      ),

    findByHashedSecret: (secretHash, kind, { tenantId }) =>
      this.run(() =>
        this._credential([eq(authCredentials.secret, secretHash), eq(authCredentials.kind, kind)], tenantId),
      ),

    findById: (id, { tenantId }) => this.run(() => this._credential([eq(authCredentials.id, id)], tenantId)),

    // NOTE: `provider`/`sub` live in free-form metadata, so the kind filter is what stops an api-key
    // answering an oauth lookup. The generated columns are what let an index reach them.
    findByProviderSub: (provider, sub, { tenantId }) =>
      this.run(() =>
        this._credential(
          [
            eq(authCredentials.kind, 'oauth'),
            eq(authCredentials.oauthProvider, provider),
            eq(authCredentials.oauthSub, sub),
          ],
          tenantId,
        ),
      ),

    listByIdentity: (identityId, kind, { tenantId }) =>
      // Newest first, id breaking a same-millisecond tie: callers take the first live row, so an
      // unordered read left the engine to decide which password or totp answers.
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

    /** Merged under the row's own lock: `json_set` writes each key where it sits. Read-then-write needed a
     *  version to hold the two halves together and a retry for when it moved. */
    patchMetadata: (id, patch, { tenantId }) =>
      this.run(async () => {
        const metadata = jsonMerged(
          sql`coalesce(${authCredentials.metadata}, cast('{}' as json))`,
          patch,
          (json) => sql`cast(${json} as json)`,
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
        const [written] = await this._db
          .update(authCredentials)
          .set({ revokedAt: new Date(), updatedBy: actorId(), version: sql`${authCredentials.version} + 1` })
          .where(reach)

        return written.affectedRows
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
        const id = authUuidV7()
        await this._db.insert(authCredentials).values({
          ...input,
          createdBy: actorId(),
          id,
          tenantId: input.tenantId ?? ctx.tenantId ?? null,
          updatedBy: actorId(),
        })

        const created = await this._credential([eq(authCredentials.id, id)], undefined)
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

    /** Either clock: `expiresAt` is the idle deadline, `absoluteExpiresAt` the ceiling it can never pass. */
    gc: (now) =>
      this.run(async () => {
        const when = new Date(now)
        const [result] = await this._db
          .delete(authSessions)
          .where(or(lt(authSessions.expiresAt, when), lt(authSessions.absoluteExpiresAt, when)))

        return { deleted: result.affectedRows }
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
        if (Object.keys(set).length > 0) await this._db.update(authSessions).set(set).where(eq(authSessions.id, id))

        const [row] = await this._db.select().from(authSessions).where(eq(authSessions.id, id)).limit(1)
        if (!row) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })

        return row
      }),
  }

  withClient(client: unknown): DrizzleMysqlAdapter<TSchema, Profile> {
    // A handle is `db` or the `tx` a transaction hands its callback, and both answer all three.
    const isHandle = (c: unknown): c is MySql2Database<TSchema> =>
      typeof c === 'object' && c !== null && 'select' in c && 'insert' in c && 'transaction' in c
    if (!isHandle(client)) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'withClient expects a drizzle mysql2 handle' })
    }

    return new DrizzleMysqlAdapter(client)
  }
}
