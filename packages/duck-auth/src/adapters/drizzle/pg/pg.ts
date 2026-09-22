import { createRequire } from 'node:module'
import { and, desc, eq, getTableColumns, gte, inArray, isNull, lt, or, type SQL, sql } from 'drizzle-orm'
import type { NodePgDatabase, NodePgQueryResultHKT } from 'drizzle-orm/node-postgres'
import { alias, type PgDatabase, type PgUpdateSetSource, type WithSubqueryWithSelection } from 'drizzle-orm/pg-core'
import { type Adapter, AdapterStore } from '~/adapters/adapter'
import { inTenant, rowsWithLinks } from '~/adapters/drizzle/drizzle.rows'
import { actorId } from '~/core/actor'
import type { Credential } from '~/core/credentials/credentials.types'
import { authUuidV7 } from '~/core/crypto'
import { AuthError, type SqlFault, STORE_RAISES } from '~/core/errors'
import { toEmailList, withNormalisedEmail } from '~/core/identities/identities.constants'
import type { Identities } from '~/core/identities/identities.types'
import { patchOrNone, stripUndefined } from '~/core/patch'
import { isFiniteNumber } from '~/core/predicates'
import type { Sessions } from '~/core/sessions/sessions.types'
import { authCredentials, authIdentities, authIdentityProviders, authSessions } from './pg.schema'
import type { Pg } from './pg.types'

const lookupLink = alias(authIdentityProviders, 'lookup_link')

export const linkFields = {
  addedAt: authIdentityProviders.addedAt,
  addedBy: authIdentityProviders.addedBy,
  providerId: authIdentityProviders.providerId,
  providerSub: authIdentityProviders.providerSub,
}

/** The row contract: every column of each table, `updated_at` included. */
const credentialColumns = getTableColumns(authCredentials)
const sessionColumns = getTableColumns(authSessions)

/** Postgres adapter over Drizzle, supplying every store the engine needs from one connection. */
export class DrizzlePgAdapter<
    TSchema extends Record<string, unknown> = Record<string, unknown>,
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  >
  extends AdapterStore<SqlFault>
  implements Adapter.Me<Profile>
{
  private readonly _db: PgDatabase<NodePgQueryResultHKT, TSchema>

  constructor(input: string | Pg.NodePgPoolLike | NodePgDatabase<TSchema>) {
    super(STORE_RAISES)
    const lazyRequire = createRequire(import.meta.url)
    this._db =
      typeof input === 'string'
        ? lazyRequire('drizzle-orm/node-postgres').drizzle(new (lazyRequire('pg').Pool)({ connectionString: input }))
        : 'select' in input
          ? input
          : lazyRequire('drizzle-orm/node-postgres').drizzle(input)
  }

  /** A live row and its logins in one join. */
  private async _find(
    by: { id: string } | { email: string } | { providerId: string; providerSub: string },
  ): Promise<Identities.Me<Profile> | null> {
    let rows = this._db
      .select({ identity: authIdentities, link: linkFields })
      .from(authIdentities)
      .leftJoin(authIdentityProviders, eq(authIdentityProviders.identityId, authIdentities.id))
      .$dynamic()

    // PERF: the answering login joins under its own alias rather than a subquery in the where. Both flatten
    // to one plan on pg; sqlite runs the subquery as a list with a temp b-tree for the order, 1.7x.
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
              ? or(...toEmailList(by.email).map((e) => sql`lower(${authIdentities.profile}->>'email') = lower(${e})`))
              : undefined,
          ),
        )
        .orderBy(authIdentityProviders.addedAt),
    )

    return row ?? null
  }

  /** The rows a write reached, with their logins. A caller that wrote one destructures the first. Inside a
   *  transaction it takes that transaction's handle; the adapter's own is a different connection, blind to
   *  what the transaction has written.
   *  WARN: a CTE's own write is invisible to the join that reads it back, so this fits a write to
   *  `auth_identities` and never one to the link table. */
  private async _linkedTo(
    written: WithSubqueryWithSelection<(typeof authIdentities)['_']['columns'], 'written'>,
    db: PgDatabase<NodePgQueryResultHKT, TSchema> = this._db,
  ): Promise<Identities.Me<Profile>[]> {
    return rowsWithLinks(
      await db
        .with(written)
        .select({ identity: written._.selectedFields, link: linkFields })
        .from(written)
        .leftJoin(authIdentityProviders, eq(authIdentityProviders.identityId, written.id))
        .orderBy(authIdentityProviders.addedAt),
    )
  }

  /** The credential a caller named: a live row before a revoked one, then the newest of those. */
  private async _credential(match: SQL[], tenantId: string | undefined): Promise<Pg.CredentialRow | null> {
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
    patch: PgUpdateSetSource<typeof authCredentials>,
  ): Promise<Pg.CredentialRow | null> {
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

  readonly identities: Identities.Store<Profile> = {
    /** One statement either way, so there is no transaction to hold open and a refused login takes the
     *  identity down with it. */
    create: (input) =>
      this.run(async () => {
        const db = this._db
        const { providers, ...columns } = withNormalisedEmail(input)
        const insert = db
          .insert(authIdentities)
          .values({ ...columns, createdBy: actorId(), deletedAt: null, deletedBy: null, updatedBy: actorId() })
          .returning()

        // NOTE: drizzle refuses `.values([])` outright, so no logins means no second write.
        if (providers.length === 0) {
          const [row] = await insert
          if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return { ...row, providers: [] as Identities.ProviderLink[] } as Identities.Me<Profile>
        }

        // SECURITY: the unique on (provider_id, provider_sub) is what refuses a login another row already
        // holds. No check runs first, so there is no window between deciding and writing.
        const written = db.$with('written').as(insert)
        const links = db.$with('links').as(
          db
            .insert(authIdentityProviders)
            .values(
              providers.map((link) => ({
                ...link,
                addedBy: actorId(),
                identityId: sql`(select ${written.id} from ${written})`,
              })),
            )
            .returning(linkFields),
        )
        const [created] = rowsWithLinks<Profile>(
          await db
            .with(written, links)
            .select({ identity: written._.selectedFields, link: links._.selectedFields })
            .from(written)
            .leftJoin(links, sql`true`),
        )
        if (!created) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

        return created
      }),

    erase: (id) =>
      this.run(async () => {
        const db = this._db
        const links = db
          .$with('links')
          .as(db.select(linkFields).from(authIdentityProviders).where(eq(authIdentityProviders.identityId, id)))
        const gone = db.$with('gone').as(db.delete(authIdentities).where(eq(authIdentities.id, id)).returning())

        const [row] = rowsWithLinks<Profile>(
          await db
            .with(links, gone)
            .select({ identity: gone._.selectedFields, link: links._.selectedFields })
            .from(gone)
            .leftJoin(links, sql`true`)
            .orderBy(links.addedAt),
        )
        if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

        return row
      }),

    /** {@link DrizzlePgAdapter.erase} over the set, in one statement: an id with no row is simply absent from the answer,
     *  which is the only thing one statement can say about a miss. Children go by FK cascade. */
    eraseMany: (ids) =>
      this.run(async () => {
        const db = this._db
        const links = db.$with('links').as(
          db
            .select({ ...linkFields, identityId: authIdentityProviders.identityId })
            .from(authIdentityProviders)
            .where(inArray(authIdentityProviders.identityId, ids)),
        )
        const gone = db.$with('gone').as(db.delete(authIdentities).where(inArray(authIdentities.id, ids)).returning())

        return rowsWithLinks<Profile>(
          await db
            .with(links, gone)
            .select({
              identity: gone._.selectedFields,
              link: {
                addedAt: links.addedAt,
                addedBy: links.addedBy,
                providerId: links.providerId,
                providerSub: links.providerSub,
              },
            })
            .from(gone)
            .leftJoin(links, eq(links.identityId, gone.id))
            .orderBy(links.addedAt),
        )
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
        const { rowCount } = await this._db.delete(authIdentities).where(lt(authIdentities.deletedAt, new Date(now)))

        return { deleted: rowCount ?? 0 }
      }),

    find: (by) =>
      this.run(async () => {
        const row = await this._find(by)
        if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

        return row
      }),

    /** The holder is the insert's own source row, so one that is gone or hidden writes nothing and the
     *  read that follows raises.
     *  SECURITY: one transaction. Both statements gate on a live row, and a `softDelete` landing between
     *  them otherwise leaves the link written while the bump matches nothing, so the caller is told the
     *  link failed while the sub stays claimed by a hidden row no other identity can take it from. */
    link: (identityId, link) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          // An insert's column list is the table's own order, so the select matches it position for position.
          const row = [
            sql.param(authUuidV7(), authIdentityProviders.id),
            authIdentities.id,
            sql.param(link.providerId, authIdentityProviders.providerId),
            sql.param(link.providerSub, authIdentityProviders.providerSub),
            sql.param(link.addedAt ?? new Date(), authIdentityProviders.addedAt),
            sql.param(actorId(), authIdentityProviders.addedBy),
          ]

          // SECURITY: (provider_id, provider_sub) refuses a login another identity holds; (identity_id,
          // provider_id) makes a repeat a no-op.
          await tx
            .insert(authIdentityProviders)
            .select(
              sql`select ${sql.join(row, sql`, `)} from ${authIdentities}
                  where ${and(eq(authIdentities.id, identityId), isNull(authIdentities.deletedAt))}`,
            )
            .onConflictDoNothing({ target: [authIdentityProviders.identityId, authIdentityProviders.providerId] })

          // The read that answers is the version bump: a login is part of what a read of the identity returns,
          // so a caller holding the old version must lose its next conditional write.
          const written = tx.$with('written').as(
            tx
              .update(authIdentities)
              .set({ version: sql`${authIdentities.version} + 1` })
              .where(and(eq(authIdentities.id, identityId), isNull(authIdentities.deletedAt)))
              .returning(),
          )
          const [linked] = await this._linkedTo(written, tx)
          if (!linked) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return linked
        }),
      ),

    restore: (id) =>
      this.run(async () => {
        const db = this._db
        const written = db.$with('written').as(
          db
            .update(authIdentities)
            .set({ deletedAt: null, deletedBy: null, version: sql`${authIdentities.version} + 1` })
            .where(and(eq(authIdentities.id, id), gte(authIdentities.deletedAt, new Date())))
            .returning(),
        )
        const [restored] = await this._linkedTo(written)
        if (restored) return restored

        // Nothing matched: the row is absent, live already, or its window has closed. Only this read sees a
        // hidden row, the one thing `find` will not answer with.
        const [found] = await db
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
        const db = this._db
        const written = db.$with('written').as(
          db
            .update(authIdentities)
            .set({
              deletedAt: new Date(Date.now() + gracePeriodMs),
              deletedBy: actorId(),
              emailVerified: false,
              version: sql`${authIdentities.version} + 1`,
            })
            .where(and(inArray(authIdentities.id, ids), isNull(authIdentities.deletedAt)))
            .returning(),
        )

        return this._linkedTo(written)
      }),

    /** SECURITY: one transaction. The delete lands before the gated bump, so a `softDelete` arriving between
     *  them otherwise leaves the login detached while the caller is told the unlink failed. */
    unlink: (identityId, providerId) =>
      this.run(() =>
        this._db.transaction(async (tx) => {
          await tx
            .delete(authIdentityProviders)
            .where(
              and(eq(authIdentityProviders.identityId, identityId), eq(authIdentityProviders.providerId, providerId)),
            )

          const written = tx.$with('written').as(
            tx
              .update(authIdentities)
              .set({ version: sql`${authIdentities.version} + 1` })
              .where(and(eq(authIdentities.id, identityId), isNull(authIdentities.deletedAt)))
              .returning(),
          )
          const [row] = await this._linkedTo(written, tx)
          if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return row
        }),
      ),

    /** SECURITY: a hidden row is not reachable. `softDelete` clears `emailVerified`, so an update landing on
     *  one hands a restored account back the verified claim the delete took away. */
    update: (id, patch, expectedVersion) =>
      this.run(async () => {
        const db = this._db
        const written = db.$with('written').as(
          db
            .update(authIdentities)
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
            .returning(),
        )
        const [row] = await this._linkedTo(written)
        if (!row) throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })

        return row
      }),
  }

  readonly credentials: Credential.Store = {
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
              sql`${authCredentials.metadata}->>'purpose' = ${purpose}`,
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

    // Newest first, id breaking a same-millisecond tie: callers take the first live row.
    listByIdentity: (identityId, kind, { tenantId }) =>
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

    /** One statement, merged under the row's own lock: `||` is jsonb's shallow merge, the object spread's. */
    patchMetadata: (id, patch, { tenantId }, expectedVersion) =>
      this.run(async () => {
        const kept = patchOrNone(patch)
        const merged = kept && sql`coalesce(${authCredentials.metadata}, '{}'::jsonb) || ${JSON.stringify(kept)}::jsonb`
        const written = await this._write(
          { expectedVersion: expectedVersion ?? null, id, tenantId },
          { metadata: merged },
        )
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
          sql`${authCredentials.metadata}->>'familyId' = ${familyId}`,
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

    create: (input, context) =>
      this.run(async () => {
        const [created] = await this._db
          .insert(authCredentials)
          .values({
            ...input,
            createdBy: actorId(),
            tenantId: input.tenantId ?? context.tenantId ?? null,
            updatedBy: actorId(),
          })
          .returning(credentialColumns)
        if (!created) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return created
      }),
  }

  readonly sessions: Sessions.Store = {
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

    deleteAllForIdentity: (identityId, context?) =>
      this.run(async () => {
        await this._db
          .delete(authSessions)
          .where(and(eq(authSessions.identityId, identityId), inTenant(authSessions.tenantId, context?.tenantId)))
      }),

    deleteMany: (ids) =>
      this.run(() =>
        this._db
          .delete(authSessions)
          .where(inArray(authSessions.id, ids))
          .returning({ id: authSessions.id, identityId: authSessions.identityId }),
      ),

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
        const { rowCount } = await this._db
          .delete(authSessions)
          .where(or(lt(authSessions.expiresAt, when), lt(authSessions.absoluteExpiresAt, when)))

        return { deleted: rowCount ?? 0 }
      }),

    getByHash: (id) =>
      this.run(async () => {
        const [row] = await this._db.select(sessionColumns).from(authSessions).where(eq(authSessions.id, id)).limit(1)
        if (!row) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })

        return row
      }),

    listByIdentity: (identityId, context?) =>
      this.run(() =>
        this._db
          .select(sessionColumns)
          .from(authSessions)
          .where(and(eq(authSessions.identityId, identityId), inTenant(authSessions.tenantId, context?.tenantId))),
      ),

    update: (id, patch) =>
      this.run(async () => {
        const db = this._db
        // A patch with nothing to say is a no-op, not a failure: `{ csrfHash: maybeToken }` is how a caller
        // says "leave it alone", and `set({})` would reach the driver as a syntax error.
        // `id` is the sid hash the caller's cookie carries: a patch naming it is dropped, never a move.
        const { id: _pinnedId, ...movable } = patch
        const set = stripUndefined(movable)
        const [row] =
          Object.keys(set).length === 0
            ? await db.select(sessionColumns).from(authSessions).where(eq(authSessions.id, id))
            : await db.update(authSessions).set(set).where(eq(authSessions.id, id)).returning(sessionColumns)
        if (!row) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })

        return row
      }),
  }

  /** Rebinds all four stores onto a transaction handle, so one unit of work shares it. */
  withClient(client: unknown): DrizzlePgAdapter<TSchema, Profile> {
    const isHandle = (c: unknown): c is NodePgDatabase<TSchema> =>
      typeof c === 'object' && c !== null && 'select' in c && 'insert' in c && 'transaction' in c
    if (!isHandle(client)) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'withClient expects a drizzle node-postgres handle' })
    }

    return new DrizzlePgAdapter(client)
  }
}

/** Constructs a {@link DrizzlePgAdapter}. */
export function drizzlePgAdapter<
  TSchema extends Record<string, unknown> = Record<string, unknown>,
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(input: string | Pg.NodePgPoolLike | NodePgDatabase<TSchema>): DrizzlePgAdapter<TSchema, Profile> {
  return new DrizzlePgAdapter<TSchema, Profile>(input)
}
