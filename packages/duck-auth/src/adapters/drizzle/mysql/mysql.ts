/** Drizzle (MySQL / MariaDB) against the three store contracts, method for method as pg reads them.
 *  WARN: no `RETURNING`, and `affectedRows` cannot tell a miss from a no-op, so a guarded write takes a lock. */

import { createRequire } from 'node:module'
import { and, desc, eq, getTableColumns, gte, inArray, isNull, lt, or, type SQL, sql } from 'drizzle-orm'
import { alias, type MySqlUpdateSetSource } from 'drizzle-orm/mysql-core'
import type { MySql2Database } from 'drizzle-orm/mysql2'
import { type Adapter, AdapterStore } from '~/adapters/adapter'
import { inTenant, jsonMerged, rowsWithLinks } from '~/adapters/drizzle/drizzle.rows'
import { actorId } from '~/core/actor'
import { authUuidV7 } from '~/core/crypto'
import { AuthError, type SqlFault, STORE_RAISES } from '~/core/errors'
import { toEmailList, withNormalisedEmail } from '~/core/identities/identities.constants'
import type { Identities } from '~/core/identities/identities.types'
import { stripUndefined } from '~/core/patch'
import { isFiniteNumber } from '~/core/predicates'
import { authCredentials, authIdentities, authIdentityProviders, authSessions } from './mysql.schema'
import type { Mysql } from './mysql.types'

/** The one link a provider lookup is answering, joined under its own name so it can drive the plan. */
const lookupLink = alias(authIdentityProviders, 'lookup_link')

const linkFields = {
  addedAt: authIdentityProviders.addedAt,
  addedBy: authIdentityProviders.addedBy,
  providerId: authIdentityProviders.providerId,
  providerSub: authIdentityProviders.providerSub,
}

/** What a read needs of a handle: `db` itself, or the `tx` a transaction hands its callback. */
type Reader = Pick<MySql2Database<Record<string, unknown>>, 'select'>

/** The row contract: each table minus its generated columns, which are index carriers and not fields. */
const { emailNorm: _emailNorm, usernameNorm: _usernameNorm, ...identityColumns } = getTableColumns(authIdentities)
const { passwordKey: _passwordKey, ...credentialColumns } = getTableColumns(authCredentials)
const sessionColumns = getTableColumns(authSessions)

/** One class: the four facets share the handle, the `STORE_RAISES` mapper and the `run` boundary that names
 *  what threw. Each is declared as its slot in `Adapter.Me`, so the contract states what it answers. */
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

  /** Same read-then-delete as {@link DrizzleMysqlAdapter._erase}, answering enough of each session to name it in the
   *  `session.revoked` the facet emits, and to say which of the ids it was handed matched a row. */
  private _eraseSessions(reach: SQL | undefined) {
    return this._db.transaction(async (tx) => {
      const going = await tx
        .select({ id: authSessions.id, identityId: authSessions.identityId })
        .from(authSessions)
        .where(reach)
        .for('update')
      if (going.length > 0) await tx.delete(authSessions).where(reach)

      return going
    })
  }

  /** The named rows and their logins, hidden ones included: what a set-based write answers with. */
  private async _rows(ids: string[], db: Reader = this._db): Promise<Identities.Me<Profile>[]> {
    return rowsWithLinks(
      await db
        .select({ identity: identityColumns, link: linkFields })
        .from(authIdentities)
        .leftJoin(authIdentityProviders, eq(authIdentityProviders.identityId, authIdentities.id))
        .where(inArray(authIdentities.id, ids))
        .orderBy(authIdentityProviders.addedAt),
    )
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

  /** A live row and its logins in one join; `hidden` is for a write reading back a row it just hid. Inside a
   *  transaction it takes that transaction's handle; the adapter's own is a different connection, blind to
   *  what the transaction has written. */
  private async _find(
    by: { id: string } | { email: string } | { providerId: string; providerSub: string },
    db: Reader = this._db,
    hidden = false,
  ) {
    let rows = db
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

    const [row] = rowsWithLinks<Profile>(
      await rows
        .where(
          and(
            hidden ? undefined : isNull(authIdentities.deletedAt),
            'id' in by ? eq(authIdentities.id, by.id) : undefined,
            // PERF: the stored column, not the expression behind it, because MySQL will not match a functional
            // index when the comparison carries the connection's collation. 24ms against 0.4ms over 50k.
            'email' in by
              ? or(...toEmailList(by.email).map((e) => eq(authIdentities.emailNorm, sql`lower(${e})`)))
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
            await tx
              .insert(authIdentityProviders)
              .values(providers.map((link) => ({ ...link, addedBy: actorId(), identityId: id })))
          }

          const created = await this._find({ id }, tx)
          if (!created) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return created
        }),
      ),

    erase: (id) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          // MySQL has no `RETURNING`, so the row is held under a lock and re-read after.
          const [locked] = await tx
            .select({ id: authIdentities.id })
            .from(authIdentities)
            .where(eq(authIdentities.id, id))
            .limit(1)
            .for('update')
          if (!locked) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          // The cascade takes the links with the row, so it is read whole while they are still there.
          const found = await this._find({ id }, tx, true)
          if (!found) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')
          await tx.delete(authIdentities).where(eq(authIdentities.id, id))

          return found
        }),
      ),

    /** `erase` over the set. Children go by FK cascade, as there. */
    eraseMany: (ids) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          const reach = inArray(authIdentities.id, ids)
          const going = await tx.select({ hit: authIdentities.id }).from(authIdentities).where(reach).for('update')
          if (going.length === 0) return []

          const rows = await this._rows(
            going.map((r) => r.hit),
            tx,
          )
          await tx.delete(authIdentities).where(reach)

          return rows
        }),
      ),

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
        const [result] = await this._db.delete(authIdentities).where(lt(authIdentities.deletedAt, new Date(now)))

        return { deleted: result.affectedRows }
      }),

    /** The holder is the insert's own source row, so one that is gone or hidden writes nothing and the
     *  read that follows raises, and the repeat is settled in the same where.
     *  SECURITY: one transaction. Both statements gate on a live row, and a `softDelete` landing between
     *  them otherwise leaves the link written while the bump matches nothing, so the caller is told the
     *  link failed while the sub stays claimed by a hidden row no other identity can take it from. */
    link: (identityId, link) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
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

          // SECURITY: (provider_id, provider_sub) refuses a login another identity holds. `on duplicate key
          // update` cannot be aimed at one index, since it would swallow the stolen sub, so the owned index is read.
          await tx.insert(authIdentityProviders).select(
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

          await tx
            .update(authIdentities)
            .set({ version: sql`${authIdentities.version} + 1` })
            .where(and(eq(authIdentities.id, identityId), isNull(authIdentities.deletedAt)))

          const linked = await this._find({ id: identityId }, tx)
          if (!linked) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return linked
        }),
      ),

    restore: (id) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          // No locked read first: this one answers the same question, and the write below is conditional
          // on the window still being open either way.
          const found = await this._find({ id }, tx, true)
          if (!found) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')
          if (!found.deletedAt) return found

          await tx
            .update(authIdentities)
            .set({ deletedAt: null, deletedBy: null, version: sql`${authIdentities.version} + 1` })
            .where(and(eq(authIdentities.id, id), gte(authIdentities.deletedAt, new Date())))

          // The re-read, not the driver's row count, is what says whether the window was still open.
          const after = await this._find({ id }, tx, true)
          if (after?.deletedAt) throw new AuthError('AUTH_GRACE_EXPIRED')
          if (!after) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return after
        }),
      ),

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
      this.run(() =>
        this._db.transaction(async (tx) => {
          const reach = and(inArray(authIdentities.id, ids), isNull(authIdentities.deletedAt))
          // The rows still live are named under lock, then hidden and read back, so the answer carries the
          // `deletedAt` and version the write just set.
          const going = await tx.select({ hit: authIdentities.id }).from(authIdentities).where(reach).for('update')
          if (going.length === 0) return []
          await tx
            .update(authIdentities)
            .set({
              deletedAt: new Date(Date.now() + gracePeriodMs),
              deletedBy: actorId(),
              emailVerified: false,
              version: sql`${authIdentities.version} + 1`,
            })
            .where(reach)

          return this._rows(
            going.map((r) => r.hit),
            tx,
          )
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

          await tx
            .update(authIdentities)
            .set({ version: sql`${authIdentities.version} + 1` })
            .where(and(eq(authIdentities.id, identityId), isNull(authIdentities.deletedAt)))

          const row = await this._find({ id: identityId }, tx)
          if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return row
        }),
      ),

    update: (id, patch, expectedVersion) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          // SECURITY: a hidden row is not reachable. `softDelete` clears `emailVerified`, so an update landing
          // on one hands a restored account back the verified claim the delete took away.
          const reach = and(
            eq(authIdentities.id, id),
            eq(authIdentities.version, expectedVersion),
            isNull(authIdentities.deletedAt),
          )
          // NOTE: it cannot name the version it found, as pg's conditional write cannot either.
          const [written] = await tx
            .update(authIdentities)
            // The row moves its own version on, so no caller can write a stale one or forget to bump it.
            .set({
              ...stripUndefined(withNormalisedEmail(patch)),
              updatedBy: actorId(),
              version: sql`${authIdentities.version} + 1`,
            })
            .where(reach)
          if (written.affectedRows === 0)
            throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })

          const row = await this._find({ id }, tx)
          if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return row
        }),
      ),
  }

  readonly credentials: Adapter.Me['credentials'] = {
    delete: (id, { tenantId }) =>
      this.run(async () => {
        const [row] = await this._erase(and(eq(authCredentials.id, id), inTenant(authCredentials.tenantId, tenantId)))
        if (!row) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return row
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

    /** Merged under the row's own lock: `json_set` writes each key where it sits. */
    patchMetadata: (id, patch, { tenantId }, expectedVersion) =>
      this.run(async () => {
        const metadata = jsonMerged(
          sql`coalesce(${authCredentials.metadata}, cast('{}' as json))`,
          patch,
          (json) => sql`cast(${json} as json)`,
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
        const row = await this._write({ expectedVersion: null, id, tenantId }, { revokedAt: new Date() })
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

    create: (input, ctx) =>
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

    deleteAllForIdentities: (identityIds) =>
      this.run(() => this._eraseSessions(inArray(authSessions.identityId, identityIds))),

    deleteAllForIdentity: (identityId, ctx?) =>
      this.run(async () => {
        await this._db
          .delete(authSessions)
          .where(and(eq(authSessions.identityId, identityId), inTenant(authSessions.tenantId, ctx?.tenantId)))
      }),

    deleteMany: (ids) => this.run(() => this._eraseSessions(inArray(authSessions.id, ids))),

    /** Either clock: `expiresAt` is the idle deadline, `absoluteExpiresAt` the ceiling it can never pass. */
    gc: (now) =>
      this.run(async () => {
        // The cutoff is the caller's, and every comparison against NaN is false while every one against
        // Infinity is true, so an unusable number does not fail - it sweeps nothing or it sweeps everything,
        // and the dialects disagreed about which.
        if (!isFiniteNumber(now)) {
          throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'gc(now) requires a finite epoch-ms cutoff' })
        }
        const when = new Date(now)
        const [result] = await this._db
          .delete(authSessions)
          .where(or(lt(authSessions.expiresAt, when), lt(authSessions.absoluteExpiresAt, when)))

        return { deleted: result.affectedRows }
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

    update: (id, patch) =>
      this.run(async () => {
        // A patch with nothing to say is a no-op, not a failure: `{ csrfHash: maybeToken }` is how a caller
        // says "leave it alone", and `set({})` would reach the driver as a syntax error.
        // `id` is the sid hash the caller's cookie carries: a patch naming it is dropped, never a move.
        const { id: _pinnedId, ...movable } = patch
        const set = stripUndefined(movable)
        if (Object.keys(set).length > 0) await this._db.update(authSessions).set(set).where(eq(authSessions.id, id))

        const [row] = await this._db.select(sessionColumns).from(authSessions).where(eq(authSessions.id, id)).limit(1)
        if (!row) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })

        return row
      }),
  }

  /** Rebinds all four stores onto a transaction handle, so one unit of work shares it. */
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

/** Constructs a {@link DrizzleMysqlAdapter}. */
export function drizzleMysqlAdapter<
  TSchema extends Record<string, unknown> = Record<string, unknown>,
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(input: string | Mysql.MySql2PoolLike | MySql2Database<TSchema>): DrizzleMysqlAdapter<TSchema, Profile> {
  return new DrizzleMysqlAdapter<TSchema, Profile>(input)
}
