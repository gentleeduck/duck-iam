import { createRequire } from 'node:module'
import { and, desc, eq, gte, inArray, isNull, lt, or, type SQL, sql } from 'drizzle-orm'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import { alias, type PgUpdateSetSource, type WithSubqueryWithSelection } from 'drizzle-orm/pg-core'
import { type Adapter, AdapterStore } from '~/adapters/adapter'
import { inTenant, rowWithLinks, stamped } from '~/adapters/drizzle/drizzle.rows'
import { actorId } from '~/core/actor'
import { outcomesFromAffected } from '~/core/batch'
import type { Credential } from '~/core/credentials/credentials.types'
import { authUuidV7 } from '~/core/crypto'
import { AuthError, type SqlFault, STORE_RAISES } from '~/core/errors'
import { toEmailList, withNormalisedEmail } from '~/core/identities/identities.constants'
import type { Identities } from '~/core/identities/identities.types'
import { patchOrNone, stripUndefined } from '~/core/patch'
import type { Sessions } from '~/core/sessions/sessions.types'
import { authCredentials, authIdentities, authIdentityProviders, authSessions } from './pg.schema'
import type { Pg } from './pg.types'

const lookupLink = alias(authIdentityProviders, 'lookup_link')

export const linkFields = {
  addedAt: authIdentityProviders.addedAt,
  providerId: authIdentityProviders.providerId,
  providerSub: authIdentityProviders.providerSub,
}

export class DrizzlePgAdapter<
    TSchema extends Record<string, unknown> = Record<string, unknown>,
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  >
  extends AdapterStore<SqlFault>
  implements Adapter.Me<Profile>
{
  private readonly _db: Pg.Handle<TSchema>

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

  /** A live row and its logins in one join. NOTE: inside a transaction it takes that transaction's handle -
   *  the adapter's own is a different connection, blind to what the transaction has written. */
  private async _find(by: Identities.By, db: Pg.Handle<TSchema> = this._db): Promise<Identities.Me<Profile> | null> {
    let rows = db
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

    return rowWithLinks(
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
  }

  /** WARN: a CTE's own write is invisible to the join that reads it back, so this fits a write to
   *  `auth_identities` and never one to the link table. */
  private async _linkedTo(
    written: WithSubqueryWithSelection<(typeof authIdentities)['_']['columns'], 'written'>,
  ): Promise<Identities.Me<Profile> | null> {
    return rowWithLinks(
      await this._db
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
      .returning()

    return row ?? null
  }

  readonly identities: Adapter.Wrapped<Identities.Store<Profile>, SqlFault> = {
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
          const bare = rowWithLinks<Profile>(row ? [{ identity: row, link: null }] : [])
          if (!bare) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return bare
        }

        // SECURITY: the unique on (provider_id, provider_sub) is what refuses a login another row already
        // holds. No check runs first, so there is no window between deciding and writing.
        const written = db.$with('written').as(insert)
        const links = db.$with('links').as(
          db
            .insert(authIdentityProviders)
            .values(providers.map((link) => ({ ...link, identityId: sql`(select ${written.id} from ${written})` })))
            .returning(linkFields),
        )
        const created = rowWithLinks<Profile>(
          await db
            .with(written, links)
            .select({ identity: written._.selectedFields, link: links._.selectedFields })
            .from(written)
            .leftJoin(links, sql`true`),
        )
        if (!created) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

        return created
      }),

    /** One statement, no transaction: every arm of a `with` reads the snapshot the statement opened on,
     *  so the links are still there to be read while the cascade under the delete takes them. */
    erase: (id) =>
      this.run(async () => {
        const db = this._db
        const links = db
          .$with('links')
          .as(db.select(linkFields).from(authIdentityProviders).where(eq(authIdentityProviders.identityId, id)))
        const gone = db.$with('gone').as(db.delete(authIdentities).where(eq(authIdentities.id, id)).returning())

        return rowWithLinks<Profile>(
          await db
            .with(links, gone)
            .select({ identity: gone._.selectedFields, link: links._.selectedFields })
            .from(gone)
            .leftJoin(links, sql`true`)
            .orderBy(links.addedAt),
        )
      }),

    find: (by) => this.run(() => this._find(by)),

    /** The holder is the insert's own source row: one that is gone or hidden writes nothing and the read
     *  answers `null`, where asking first cost a round trip. */
    link: (identityId, link) =>
      this.run(async () => {
        const db = this._db
        // An insert's column list is the table's own order, so the select matches it position for position.
        const row = [
          sql.param(authUuidV7(), authIdentityProviders.id),
          authIdentities.id,
          sql.param(link.providerId, authIdentityProviders.providerId),
          sql.param(link.providerSub, authIdentityProviders.providerSub),
          sql.param(link.addedAt ?? new Date(), authIdentityProviders.addedAt),
        ]

        // SECURITY: (provider_id, provider_sub) refuses a login another identity holds; (identity_id,
        // provider_id) makes a repeat a no-op.
        await db
          .insert(authIdentityProviders)
          .select(
            sql`select ${sql.join(row, sql`, `)} from ${authIdentities}
                where ${and(eq(authIdentities.id, identityId), isNull(authIdentities.deletedAt))}`,
          )
          .onConflictDoNothing({ target: [authIdentityProviders.identityId, authIdentityProviders.providerId] })

        return this._find({ id: identityId }, db)
      }),

    /** One transaction: the dup's credentials, sessions and logins are re-pointed before it is deleted, since
     *  the FK cascade would take them with it, and a missing side rolls the whole thing back. */
    merge: (survivorId, dupId) =>
      this.run(async () => {
        const db = this._db
        if (survivorId === dupId) return this._find({ id: survivorId }, db)

        return db.transaction(async (tx) => {
          // SECURITY: both sides are confirmed before anything moves. A merge that re-points the dup's rows
          // and only then finds the survivor gone has destroyed the dup for nothing.
          const present = await tx
            .select({ id: authIdentities.id })
            .from(authIdentities)
            .where(inArray(authIdentities.id, [survivorId, dupId]))
          if (present.length !== 2) return null

          // Two live passwords leave the row that answers a login up to the engine, so only a kind the
          // survivor already holds in the same tenant goes.
          await tx.delete(authCredentials).where(
            and(
              eq(authCredentials.identityId, dupId),
              isNull(authCredentials.revokedAt),
              inArray(authCredentials.kind, ['password', 'totp']),
              sql`exists (
                    select 1 from ${authCredentials} kept
                    where kept.identity_id = ${survivorId}
                      and kept.revoked_at is null
                      and kept.kind = ${authCredentials.kind}
                      and kept.tenant_id is not distinct from ${authCredentials.tenantId}
                  )`,
            ),
          )

          await tx.update(authCredentials).set({ identityId: survivorId }).where(eq(authCredentials.identityId, dupId))
          await tx.update(authSessions).set({ identityId: survivorId }).where(eq(authSessions.identityId, dupId))

          // A provider both rows held clashes on the owned index, so the dup's copy stays put and the
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

          return this._find({ id: survivorId }, tx)
        })
      }),

    restore: (id) =>
      this.run(async () => {
        const db = this._db
        const written = db.$with('written').as(
          db
            .update(authIdentities)
            .set({ deletedAt: null, deletedBy: null })
            .where(and(eq(authIdentities.id, id), gte(authIdentities.deletedAt, new Date())))
            .returning(),
        )
        const restored = await this._linkedTo(written)
        if (restored) return restored

        // Nothing matched: the row is absent, live already, or its window has closed. Only this read sees a
        // hidden row, the one thing `find` will not answer with.
        const [found] = await db
          .select({ deletedAt: authIdentities.deletedAt })
          .from(authIdentities)
          .where(eq(authIdentities.id, id))
          .limit(1)
        if (!found) return null
        if (found.deletedAt) throw new AuthError('AUTH_GRACE_EXPIRED')

        return this._find({ id }, db)
      }),

    softDelete: (id, gracePeriodMs) =>
      this.run(() => {
        const db = this._db
        // `deletedAt` is when the grace window closes, not when the delete happened.
        const written = db.$with('written').as(
          db
            .update(authIdentities)
            .set({
              deletedAt: new Date(Date.now() + gracePeriodMs),
              deletedBy: actorId(),
              emailVerified: false,
            })
            .where(and(eq(authIdentities.id, id), isNull(authIdentities.deletedAt)))
            .returning(),
        )

        return this._linkedTo(written)
      }),

    unlink: (identityId, providerId) =>
      this.run(async () => {
        const db = this._db
        await db
          .delete(authIdentityProviders)
          .where(
            and(eq(authIdentityProviders.identityId, identityId), eq(authIdentityProviders.providerId, providerId)),
          )

        return this._find({ id: identityId }, db)
      }),

    update: (id, patch, expectedVersion) =>
      this.run(async () => {
        const db = this._db
        const written = db.$with('written').as(
          db
            .update(authIdentities)
            .set({ ...stamped(withNormalisedEmail(patch)), version: sql`${authIdentities.version} + 1` })
            .where(and(eq(authIdentities.id, id), eq(authIdentities.version, expectedVersion)))
            .returning(),
        )
        const row = await this._linkedTo(written)
        if (!row) throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })

        return row
      }),
  }

  readonly credentials: Adapter.Wrapped<Credential.Store, SqlFault> = {
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
              sql`${authCredentials.metadata}->>'purpose' = ${purpose}`,
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
            sql`${authCredentials.metadata}->>'provider' = ${provider}`,
            sql`${authCredentials.metadata}->>'sub' = ${sub}`,
          ],
          tenantId,
        ),
      ),

    // Newest first, id breaking a same-millisecond tie: callers take the first live row, so an unordered
    // read left the engine to decide which password or totp answers.
    listByIdentity: (identityId, kind, { tenantId }) =>
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

    /** One statement, merged under the row's own lock: `||` is jsonb's shallow merge, the object spread's.
     *  Read-then-write needed a version and a retry to hold the two halves together. */
    patchMetadata: (id, patch, { tenantId }) =>
      this.run(async () => {
        const kept = patchOrNone(patch)
        const merged = kept && sql`coalesce(${authCredentials.metadata}, '{}'::jsonb) || ${JSON.stringify(kept)}::jsonb`
        const written = await this._write({ expectedVersion: null, id, tenantId }, { metadata: merged })
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

    upsert: (input, context) =>
      this.run(async () => {
        const [created] = await this._db
          .insert(authCredentials)
          .values({
            ...input,
            createdBy: actorId(),
            tenantId: input.tenantId ?? context.tenantId ?? null,
            updatedBy: actorId(),
          })
          .returning()
        if (!created) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return created
      }),
  }

  readonly sessions: Adapter.Wrapped<Sessions.Store, SqlFault> = {
    /** The row arrives whole - its id is the token hash the caller computed - so nothing here is stamped. */
    create: (session) =>
      this.run(async () => {
        await this._db.insert(authSessions).values(session)
      }),

    delete: (id) =>
      this.run(async () => {
        await this._db.delete(authSessions).where(eq(authSessions.id, id))
      }),

    /** One statement for the whole set. `RETURNING` names the identities that actually had a session,
     *  which is the only way one statement can report a miss per row. */
    deleteAllForIdentities: (identityIds) =>
      this.run(async () => {
        const gone = await this._db
          .delete(authSessions)
          .where(inArray(authSessions.identityId, [...identityIds]))
          .returning({ identityId: authSessions.identityId })

        return outcomesFromAffected(
          identityIds,
          gone.map((r) => r.identityId),
        )
      }),

    deleteAllForIdentity: (identityId, context?) =>
      this.run(async () => {
        await this._db
          .delete(authSessions)
          .where(and(eq(authSessions.identityId, identityId), inTenant(authSessions.tenantId, context?.tenantId)))
      }),

    deleteMany: (ids) =>
      this.run(async () => {
        const gone = await this._db
          .delete(authSessions)
          .where(inArray(authSessions.id, [...ids]))
          .returning({ id: authSessions.id })

        return outcomesFromAffected(
          ids,
          gone.map((r) => r.id),
        )
      }),

    /** Either clock: `expiresAt` is the idle deadline, `absoluteExpiresAt` the ceiling it can never pass. */
    gc: (now) =>
      this.run(async () => {
        const when = new Date(now)
        const { rowCount } = await this._db
          .delete(authSessions)
          .where(or(lt(authSessions.expiresAt, when), lt(authSessions.absoluteExpiresAt, when)))

        return { deleted: rowCount ?? 0 }
      }),

    getByHash: (id) =>
      this.run(async () => {
        const [row] = await this._db.select().from(authSessions).where(eq(authSessions.id, id)).limit(1)

        return row ?? null
      }),

    listByIdentities: (identityIds) =>
      this.run(() =>
        this._db
          .select()
          .from(authSessions)
          .where(inArray(authSessions.identityId, [...identityIds])),
      ),

    listByIdentity: (identityId, context?) =>
      this.run(() =>
        this._db
          .select()
          .from(authSessions)
          .where(and(eq(authSessions.identityId, identityId), inTenant(authSessions.tenantId, context?.tenantId))),
      ),

    update: (id, patch) =>
      this.run(async () => {
        const db = this._db
        // A patch with nothing to say is a no-op, not a failure: `{ csrfHash: maybeToken }` is how a caller
        // says "leave it alone", and `set({})` would reach the driver as a syntax error.
        const set = stripUndefined(patch)
        const [row] =
          Object.keys(set).length === 0
            ? await db.select().from(authSessions).where(eq(authSessions.id, id))
            : await db.update(authSessions).set(set).where(eq(authSessions.id, id)).returning()
        if (!row) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })

        return row
      }),
  }

  withClient(client: unknown): DrizzlePgAdapter<TSchema, Profile> {
    const isHandle = (c: unknown): c is NodePgDatabase<TSchema> =>
      typeof c === 'object' && c !== null && 'select' in c && 'insert' in c && 'transaction' in c
    if (!isHandle(client)) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'withClient expects a drizzle node-postgres handle' })
    }

    return new DrizzlePgAdapter(client)
  }
}
