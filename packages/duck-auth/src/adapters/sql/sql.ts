import { actorId } from '~/core/actor'
import { type Batch, batchResult } from '~/core/batch'
import type { Credential } from '~/core/credentials/credentials.types'
import { authUlid } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import { stripUndefined } from '~/core/patch'
import { AUTH_SESSION_FACTOR_METHODS, type Sessions } from '~/core/sessions/sessions.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
import type { SqlBridge } from './sql.types'

export function pickFreshestCredential(rows: readonly Credential.Me[]): Credential.Me | null {
  let live: Credential.Me | null = null
  let revoked: Credential.Me | null = null
  for (const c of rows) {
    const t = c.createdAt.getTime()
    if (c.revokedAt) {
      if (!revoked || t > revoked.createdAt.getTime()) revoked = c
    } else if (!live || t > live.createdAt.getTime()) {
      live = c
    }
  }
  return live ?? revoked
}

/**
 * Reads `profile.email` without asserting a shape onto it. `profile` is a JSON
 * column, so what comes back is whatever was stored - the schema CHECK asks
 * only that the key exists, not that it holds a string.
 */
export function profileEmail(profile: unknown): string | undefined {
  if (typeof profile !== 'object' || profile === null) return undefined
  if (!('email' in profile)) return undefined
  return typeof profile.email === 'string' ? profile.email : undefined
}

/**
 * Shared by every dialect bridge's `restore`.
 *
 * `deletedAt` holds the moment the grace window *closes*, not the moment of
 * deletion, so a row is restorable only while that moment is still ahead. The
 * SQL bridges used to clear `deletedAt` unconditionally, which brought back
 * accounts whose window had long since closed - including ones already queued
 * for hard purge - while the memory adapter refused them. This makes the
 * dialects agree with the memory adapter rather than the other way round.
 */
export function isRestorable(row: { deletedAt: Date | null }): boolean {
  const closesAt = row.deletedAt?.getTime()
  return closesAt !== undefined && closesAt >= Date.now()
}

/**
 * The throwing twin, for the single-row path. `restoreMany` needs the predicate
 * instead: it decides per row and keeps going, reporting a refusal as a soft
 * failure rather than aborting the batch. Both are one rule expressed once, so
 * the batch and single-row forms cannot drift into disagreeing about when a
 * grace window has closed.
 */
export function assertRestorable(row: { deletedAt: Date | null }): void {
  if (!isRestorable(row)) throw new AuthError('AUTH_GRACE_EXPIRED')
}

/**
 * Restoring must not resurrect a claim on an address someone else now holds.
 * The unique indexes are partial on `deletedAt`, so the address was free the
 * whole time the row was hidden; without this the `UPDATE` trips the index and
 * surfaces a raw driver error instead of a typed one, and an adapter with no
 * such index (memory) would simply end up with two live rows sharing an email.
 */
export function assertEmailFree(email: string | undefined, taken: boolean): void {
  if (email !== undefined && taken) throw new AuthError('AUTH_EMAIL_TAKEN')
}

/**
 * The same rule as {@link assertEmailFree}, for provider logins.
 *
 * `findByProviderSub` skips soft-deleted rows, so while a row is hidden its
 * `(providerId, providerSub)` pairs are free for someone else to claim - and
 * nothing stops them, because the providers array is JSON with no unique index
 * behind it. Restoring without this check produces two live rows answering to
 * one provider identity, and `findByProviderSub` then returns whichever the
 * dialect happened to order first: the deleted account silently takes over the
 * new one's Google login, or the reverse, depending on the query plan.
 */
export function assertProviderSubFree(clash: { providerId: string } | undefined): void {
  if (clash !== undefined) throw new AuthError('AUTH_PROVIDER_TAKEN', { providerId: clash.providerId })
}

/**
 * The unique indexes behind email and username, by the name every dialect
 * reports when one is violated.
 *
 * The pre-checks above are read-then-write and so are racy by construction: two
 * concurrent signups both read a free address, both insert, and the index
 * refuses the loser. That refusal is correct - it is the only thing that makes
 * the address unique at all - but it arrived as a raw driver error, so the same
 * conflict surfaced as `AUTH_EMAIL_TAKEN` when the pre-check caught it and as a
 * 500 when the index did. The database is the authority here; this just gives
 * its answer the same name the pre-check uses.
 */
const UNIQUE_INDEX_ERRORS = [
  { code: 'AUTH_EMAIL_TAKEN', index: 'uq_auth_identities_email' },
  { code: 'AUTH_USERNAME_TAKEN', index: 'uq_auth_identities_username' },
] as const

/**
 * Everything a driver might have written the index name into. pg puts it on
 * `constraint`, mysql2 and sqlite only in the message, and a driver is free to
 * nest the real error under `cause` - so all of them are searched rather than
 * betting on one shape.
 */
function errorText(err: unknown): string {
  if (typeof err === 'string') return err
  if (err === null || typeof err !== 'object') return ''
  const parts: string[] = []
  for (const key of ['message', 'constraint', 'detail', 'sqlMessage'] as const) {
    const value = Reflect.get(err, key)
    if (typeof value === 'string') parts.push(value)
  }
  const cause = Reflect.get(err, 'cause')
  if (cause !== undefined && cause !== err) parts.push(errorText(cause))
  return parts.join(' ')
}

/**
 * Run a write, and rename a unique-index violation to the typed error for that
 * index. Anything else propagates untouched: a driver error that is not one of
 * these is a real failure and must not be dressed up as a conflict.
 */
export async function mapUniqueViolations<T>(write: () => Promise<T>): Promise<T> {
  try {
    return await write()
  } catch (err) {
    if (err instanceof AuthError) throw err
    const text = errorText(err)
    const hit = UNIQUE_INDEX_ERRORS.find((candidate) => text.includes(candidate.index))
    if (hit === undefined) throw err
    const typed = new AuthError(hit.code)
    // The driver error stays reachable for logs; the typed code is what callers match on.
    typed.cause = err
    throw typed
  }
}

/**
 * Set key for one provider claim. `\u0000` cannot occur in either half of a
 * real pair, so it cannot be forged by a provider id that merely contains the
 * separator.
 */
export function providerSubKey(claim: { providerId: string; providerSub: string }): string {
  return `${claim.providerId}\u0000${claim.providerSub}`
}

/**
 * The pairs a restoring row would re-claim. Empty for a row with no provider
 * logins, or one whose links carry no `providerSub` - a null sub identifies
 * nobody and so can never clash.
 */
export function claimedProviderSubs(row: {
  providers: readonly { providerId: string; providerSub: string | null }[]
}): { providerId: string; providerSub: string }[] {
  const out: { providerId: string; providerSub: string }[] = []
  for (const link of row.providers) {
    if (typeof link.providerSub === 'string' && link.providerSub.length > 0) {
      out.push({ providerId: link.providerId, providerSub: link.providerSub })
    }
  }
  return out
}

export function createSqlStores<Profile extends Identities.ProfileMetadataBase>(
  bridge: SqlBridge.Me<Profile>,
): {
  identities: Identities.Store<Profile>
  credentials: Credential.Store
  sessions: Sessions.Store
} {
  const identities = buildIdentities<Profile>(bridge.identities)
  const credentials = buildCredentials(bridge.credentials)
  const sessions = buildSessions(bridge.sessions)

  // One bridge-level rebind covers all three stores: re-make the bridge against
  // the caller's client, then rebuild the stores from it. Adapters therefore
  // implement `withClient` once, not once per store.
  const rebind = bridge.withClient
  if (rebind) {
    identities.withClient = (client) => createSqlStores<Profile>(rebind(client)).identities
    credentials.withClient = (client) => createSqlStores<Profile>(rebind(client)).credentials
    sessions.withClient = (client) => createSqlStores<Profile>(rebind(client)).sessions
  }

  return { identities, credentials, sessions }
}

/**
 * Turns "ids I asked for" plus "ids the statement actually touched" into
 * per-row outcomes in input order.
 *
 * An id the statement did not touch is `not-found` - which is exactly what a
 * `WHERE id = ANY($1)` matching fewer rows than it was given means.
 */
function outcomesFromAffected(requested: readonly string[], affected: readonly string[]): Batch.Result {
  const hit = new Set(affected)
  return batchResult(
    requested.map((id) =>
      hit.has(id)
        ? { id, ok: true as const, value: undefined }
        : { id, ok: false as const, reason: 'not-found' as const },
    ),
  )
}

/** Outcome id for a provider link; mirrors the facet's key so outcomes line up. */
function linkKey(identityId: string, providerId: string): string {
  return `${identityId} ${providerId}`
}

/**
 * A `Date` handed to a JSON column comes back as the ISO string
 * `JSON.stringify` wrote. Three typed-`Date` fields live inside
 * `jsonb`/`json`/`text` columns: `providers[].addedAt`, a session's
 * `factors[].completedAt`, and both dates on `actingAs`. The memory and Redis
 * stores hand back real `Date`s, so leaving these as strings made the SQL
 * adapters the odd ones out - and the row types kept promising `Date`, so it
 * surfaced in caller code as `addedAt.getTime is not a function` rather than
 * here. `parseStoredDate` in the Redis session store does this same job.
 */
function storedDate(value: unknown): Date | null {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null
  if (typeof value === 'string') {
    const parsed = new Date(value)
    return Number.isFinite(parsed.getTime()) ? parsed : null
  }
  if (typeof value === 'number' && Number.isFinite(value)) return new Date(value)
  return null
}

/**
 * `$type<ProviderLink[]>()` is a compile-time assertion drizzle makes about a
 * JSON column; the database enforces `NOT NULL` and nothing else. A row written
 * by an older migration, another service, or a hand-run `UPDATE` can hold
 * `null`, `{}`, `"..."` or `[1, 2]` in that column, and every one of those used
 * to reach `.length`/`.map` and throw a `TypeError` out of a plain `findById`.
 * The Redis store already answers `[]` for the same input; failing soft here
 * keeps a malformed row from taking the whole request down with it.
 */
function isProviderLink(value: unknown): value is Identities.ProviderLink {
  if (typeof value !== 'object' || value === null) return false
  if (!('providerId' in value) || typeof value.providerId !== 'string') return false
  if (!('providerSub' in value)) return false
  return value.providerSub === null || typeof value.providerSub === 'string'
}

/**
 * A link whose `addedAt` is unreadable keeps the link and falls back to the
 * row's own `createdAt`: the date is informational, while dropping the entry
 * would silently remove a way into the account. A link missing its `providerId`
 * is a different matter - it can never match a lookup, so keeping it would only
 * inflate the array.
 */
function reviveIdentity<Profile extends Identities.ProfileMetadataBase>(
  row: Identities.Me<Profile>,
): Identities.Me<Profile> {
  if (!Array.isArray(row.providers)) return { ...row, providers: [] }
  if (row.providers.length === 0) return row
  return {
    ...row,
    providers: row.providers
      .filter(isProviderLink)
      .map((link) => ({ ...link, addedAt: storedDate(link.addedAt) ?? row.createdAt })),
  }
}

const reviveIdentityOrNull = <Profile extends Identities.ProfileMetadataBase>(
  row: Identities.Me<Profile> | null,
): Identities.Me<Profile> | null => (row ? reviveIdentity(row) : null)

/**
 * `factors[].completedAt` falls back to the session's `createdAt` - a factor
 * that was completed is still completed whether or not its timestamp survived.
 * `actingAs` gets no such fallback: an impersonation window whose start or end
 * cannot be read is not a window anyone should be inside, so it is dropped,
 * matching the Redis store.
 */
function isFactor(value: unknown): value is Sessions.Factor {
  if (typeof value !== 'object' || value === null) return false
  if (!('method' in value)) return false
  return AUTH_SESSION_FACTOR_METHODS.some((method) => method === value.method)
}

function reviveSession(row: Sessions.Me): Sessions.Me {
  // Same story as `providers`: the column is `NOT NULL` json, which excludes SQL
  // NULL and nothing else. A factor whose `method` is outside the union is
  // dropped rather than carried, matching the Redis store - an AAL decision has
  // to read the same on every backend, and a method no `switch` handles is worse
  // than one that is simply absent.
  const rawFactors = Array.isArray(row.factors) ? row.factors : []
  const factors = rawFactors
    .filter(isFactor)
    .map((f) => ({ ...f, completedAt: storedDate(f.completedAt) ?? row.createdAt }))
  if (!row.actingAs) return { ...row, factors }
  const startedAt = storedDate(row.actingAs.startedAt)
  const expiresAt = storedDate(row.actingAs.expiresAt)
  return {
    ...row,
    actingAs: startedAt && expiresAt ? { ...row.actingAs, expiresAt, startedAt } : null,
    factors,
  }
}

const reviveSessionOrNull = (row: Sessions.Me | null): Sessions.Me | null => (row ? reviveSession(row) : null)

function buildIdentities<Profile extends Identities.ProfileMetadataBase>(
  bridge: SqlBridge.Identity<Identities.Me<Profile>>,
): Identities.Store<Profile> {
  // Hoisted so the `&&` guard below narrows a `const` the closure captures.
  // Reading `bridge.x` again inside the closure would be `x | undefined` all
  // over again, and the only way back would be a `!` the type system cannot
  // check.
  //
  // Bound, not destructured: `SqlBridge.Identity` is an interface, so a caller
  // may implement it as a class, and a bare `const { x } = bridge` would drop
  // the `this` its methods need.
  const softDeleteManyReturningIds = bridge.softDeleteManyReturningIds?.bind(bridge)
  const eraseManyReturningIds = bridge.eraseManyReturningIds?.bind(bridge)
  const restoreManyReturning = bridge.restoreManyReturning?.bind(bridge)
  const updateProfileManyReturning = bridge.updateProfileManyReturning?.bind(bridge)
  const insertProviderLinks = bridge.insertProviderLinks?.bind(bridge)
  const deleteProviderLinks = bridge.deleteProviderLinks?.bind(bridge)
  return {
    findById: async (id) => reviveIdentityOrNull(await bridge.findById(id)),
    findByEmail: async (email) => reviveIdentityOrNull(await bridge.findByEmail(email)),
    findByProviderSub: async (providerId, sub) => reviveIdentityOrNull(await bridge.findByProviderSub(providerId, sub)),
    create: async (input) => {
      const now = new Date()
      const row: Identities.Me<Profile> = {
        id: authUlid(),
        profile: input.profile,
        providers: input.providers ?? [],
        version: 1,
        emailVerified: input.emailVerified ?? false,
        createdAt: now,
        updatedAt: now,
        deletedAt: null,
        deletedBy: null,
        // Both, not just `createdBy`: `updatedAt` is also `now` on an insert,
        // so the row's last writer is its creator.
        createdBy: actorId(),
        updatedBy: actorId(),
      }
      await mapUniqueViolations(() => bridge.insert(row))
      return row
    },
    update: async (id, patch, expectedVersion) => {
      const sqlPatch = {
        ...stripUndefined(patch),
        updatedAt: new Date(),
        updatedBy: actorId(),
        version: expectedVersion + 1,
      }
      const next = await mapUniqueViolations(() => bridge.updateConditional(id, sqlPatch, expectedVersion))
      if (!next) throw new AuthError('AUTH_STALE_WRITE', { expected: expectedVersion, actual: -1 })
      return reviveIdentity(next)
    },
    softDelete: async (id, gracePeriodMs) =>
      reviveIdentityOrNull(await bridge.softDelete(id, new Date(Date.now() + gracePeriodMs), actorId())),
    // The pre-checks inside a dialect's `restore` are the typed path; this
    // catches the same clash when a concurrent write wins the race between them
    // and the UPDATE, which no amount of checking first can close.
    restore: async (id) => reviveIdentityOrNull(await mapUniqueViolations(() => bridge.restore(id))),
    erase: async (id) => reviveIdentityOrNull(await bridge.erase(id)),
    link: async (identityId, link) =>
      reviveIdentityOrNull(
        await bridge.insertProviderLink(identityId, link.providerId, link.providerSub, link.addedAt),
      ),
    unlink: async (identityId, providerId) =>
      reviveIdentityOrNull(await bridge.deleteProviderLink(identityId, providerId)),
    merge: async (survivorId, dupId) => reviveIdentityOrNull(await bridge.merge(survivorId, dupId)),

    ...(softDeleteManyReturningIds && {
      softDeleteMany: async (ids: readonly string[], gracePeriodMs: number) =>
        outcomesFromAffected(
          ids,
          await softDeleteManyReturningIds(ids, new Date(Date.now() + gracePeriodMs), actorId()),
        ),
    }),

    ...(eraseManyReturningIds && {
      eraseMany: async (ids: readonly string[]) => outcomesFromAffected(ids, await eraseManyReturningIds(ids)),
    }),

    ...(restoreManyReturning && {
      restoreMany: async (ids: readonly string[]) => {
        const { candidates, refused, restored } = await restoreManyReturning(ids)
        const seen = new Map(candidates.map((row) => [row.id, row]))
        const byId = new Map(restored.map((row) => [row.id, row]))
        const why = new Map((refused ?? []).map((r) => [r.id, r.reason]))
        return batchResult(
          ids.map((id) => {
            const row = byId.get(id)
            if (row) return { id, ok: true as const, value: reviveIdentity(row) }
            const candidate = seen.get(id)
            // The id matched nothing at all - the only case that is really absent.
            if (!candidate) return { id, ok: false as const, reason: 'not-found' as const }
            if (!isRestorable(candidate)) return { id, ok: false as const, reason: 'grace-expired' as const }
            // Inside its window and still refused means a clash, and the
            // dialect ran both clash queries so it is the one that can say
            // which. `email-taken` is the fallback for a custom bridge that
            // does not report reasons - it was the only clash before provider
            // subs were guarded, so it stays the more conservative guess.
            return { id, ok: false as const, reason: why.get(id) ?? ('email-taken' as const) }
          }),
        )
      },
    }),

    ...(updateProfileManyReturning && {
      updateProfileMany: async (rows: readonly { id: string; profile: Profile; expectedVersion: number }[]) => {
        // One statement for the whole batch, so a unique violation fails all of
        // it - but as `AUTH_EMAIL_TAKEN`, which `toSoftReason` knows, rather
        // than a raw driver error the caller cannot classify.
        const updated = await mapUniqueViolations(() =>
          updateProfileManyReturning(
            rows.map((r) => ({
              expectedVersion: r.expectedVersion,
              id: r.id,
              // `updatedBy` travels with `updatedAt`: a batch that moves the
              // timestamp without moving the writer would leave the row claiming
              // its previous author made this change.
              patch: {
                profile: r.profile,
                updatedAt: new Date(),
                updatedBy: actorId(),
                version: r.expectedVersion + 1,
              },
            })),
          ),
        )
        const byId = new Map(updated.map((row) => [row.id, row]))
        // A requested id missing from the response is `stale-write`, not
        // `not-found`: the facet already proved the row exists, so the only way
        // the conditional update matched nothing is a version mismatch.
        return batchResult(
          rows.map((r) => {
            const row = byId.get(r.id)
            return row
              ? { id: r.id, ok: true as const, value: reviveIdentity(row) }
              : { id: r.id, ok: false as const, reason: 'stale-write' as const }
          }),
        )
      },
    }),

    ...(insertProviderLinks && {
      linkMany: async (links: readonly { identityId: string; link: Identities.ProviderLink }[]) =>
        outcomesFromAffected(
          links.map((l) => linkKey(l.identityId, l.link.providerId)),
          await insertProviderLinks(
            links.map((l) => ({
              addedAt: l.link.addedAt,
              identityId: l.identityId,
              providerId: l.link.providerId,
              providerSub: l.link.providerSub,
            })),
          ),
        ),
    }),

    ...(deleteProviderLinks && {
      unlinkMany: async (links: readonly { identityId: string; providerId: string }[]) =>
        outcomesFromAffected(
          links.map((l) => linkKey(l.identityId, l.providerId)),
          await deleteProviderLinks([...links]),
        ),
    }),
  }
}

function buildCredentials(bridge: SqlBridge.Credential<Credential.Me>): Credential.Store {
  // Bound, not destructured - see the note in `buildIdentities`.
  const deleteByIdentitiesReturningIds = bridge.deleteByIdentitiesReturningIds?.bind(bridge)
  return {
    findById: (id, ctx) => bridge.findById(id, ctx.tenantId),
    listByIdentity: (identityId, kind, ctx) => bridge.listByIdentity(identityId, kind, ctx.tenantId),
    findByProviderSub: (provider, sub, ctx) => bridge.findByProviderSub(provider, sub, ctx.tenantId),
    findByHashedSecret: (secretHash, kind, ctx) => bridge.findByHashedSecret(secretHash, kind, ctx.tenantId),
    upsert: async (input, ctx) => {
      const row: Credential.Me = {
        createdBy: actorId(),
        updatedBy: actorId(),
        id: authUlid(),
        identityId: input.identityId,
        tenantId: input.tenantId ?? ctx.tenantId ?? null,
        kind: input.kind,
        secret: input.secret,
        metadata: input.metadata ?? null,
        version: 1,
        createdAt: new Date(),
        lastUsedAt: input.lastUsedAt ?? null,
        expiresAt: input.expiresAt ?? null,
        revokedAt: input.revokedAt ?? null,
      }
      await bridge.insert(row)
      return row
    },
    rotate: async (id, newSecret, expectedVersion, ctx) => {
      const next = await bridge.updateConditional(
        id,
        { secret: newSecret, version: expectedVersion + 1, lastUsedAt: new Date() },
        expectedVersion,
        ctx.tenantId,
      )
      if (!next) throw new AuthError('AUTH_STALE_WRITE', { expected: expectedVersion, actual: -1 })
      return next
    },
    patchMetadata: async (id, patch, ctx) => {
      for (let attempt = 0; attempt < 2; attempt++) {
        const row = await bridge.findById(id, ctx.tenantId)
        // One code for "the conditional write matched no row". The retry below
        // already reports a lost race as AUTH_STALE_WRITE, and a caller cannot
        // act differently on the two: an id that is gone and an id that moved
        // both mean re-read and decide again.
        if (!row) throw new AuthError('AUTH_STALE_WRITE', { expected: -1, actual: -1 })
        const next = await bridge.updateConditional(
          id,
          { metadata: { ...(row.metadata ?? {}), ...patch }, version: row.version + 1 },
          row.version,
          ctx.tenantId,
        )
        if (next) return next
      }
      throw new AuthError('AUTH_STALE_WRITE', { expected: -1, actual: -1 })
    },
    revoke: (id, ctx) => bridge.revoke(id, new Date(), ctx.tenantId),
    delete: (id, ctx) => bridge.delete(id, ctx.tenantId),
    deleteByKind: (identityId, kind, ctx) => bridge.deleteByKind(identityId, kind, ctx.tenantId),

    ...(deleteByIdentitiesReturningIds && {
      deleteByIdentities: async (identityIds: readonly string[], ctx: TenantContext) =>
        outcomesFromAffected(identityIds, await deleteByIdentitiesReturningIds(identityIds, ctx.tenantId)),
    }),
  }
}

function buildSessions(bridge: SqlBridge.Session<Sessions.Me>): Sessions.Store {
  // Bound, not destructured - see the note in `buildIdentities`.
  const deleteAllForIdentitiesReturningIds = bridge.deleteAllForIdentitiesReturningIds?.bind(bridge)
  const deleteManyReturningIds = bridge.deleteManyReturningIds?.bind(bridge)
  const listByIdentities = bridge.listByIdentities?.bind(bridge)
  return {
    create: async (s) => {
      await bridge.insert({
        id: s.id,
        identityId: s.identityId,
        tenantId: s.tenantId ?? null,
        kind: s.kind,
        aal: s.aal,
        factors: s.factors,
        csrfHash: s.csrfHash ?? null,
        ip: s.ip ?? null,
        userAgent: s.userAgent ?? null,
        fingerprint: s.fingerprint ?? null,
        createdAt: s.createdAt,
        rotatedAt: s.rotatedAt,
        expiresAt: s.expiresAt,
        absoluteExpiresAt: s.absoluteExpiresAt,
        fresh: s.fresh,
        actingAs: s.actingAs ?? null,
      })
    },
    getByHash: async (sidHash) => reviveSessionOrNull(await bridge.findByHash(sidHash)),
    update: async (id, patch) => {
      const next = await bridge.update(id, stripUndefined(patch))
      if (!next) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })
      return reviveSession(next)
    },
    delete: (id) => bridge.delete(id),
    listByIdentity: async (identityId) => (await bridge.listByIdentity(identityId)).map(reviveSession),
    deleteAllForIdentity: (identityId) => bridge.deleteAllForIdentity(identityId),
    gc: async (now) => ({ deleted: await bridge.deleteExpired(new Date(now)) }),

    ...(deleteAllForIdentitiesReturningIds && {
      deleteAllForIdentities: async (identityIds: readonly string[]) =>
        outcomesFromAffected(identityIds, await deleteAllForIdentitiesReturningIds(identityIds)),
    }),

    ...(deleteManyReturningIds && {
      deleteMany: async (ids: readonly string[]) => outcomesFromAffected(ids, await deleteManyReturningIds(ids)),
    }),

    ...(listByIdentities && {
      listByIdentities: async (identityIds: readonly string[]) =>
        (await listByIdentities(identityIds)).map(reviveSession),
    }),
  }
}
