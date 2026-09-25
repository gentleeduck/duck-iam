import { type Adapter, AdapterStore } from '~/adapters/adapter'
import { actorId } from '~/core/actor'
import { getCredentialPurpose, isRevoked } from '~/core/credentials/credentials'
import { AUTH_CREDENTIAL_KINDS } from '~/core/credentials/credentials.constants'
import type { Credential } from '~/core/credentials/credentials.types'
import { authUuidV7, timingSafeEqual } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import { isSoftDeleted } from '~/core/identities/identities'
import { assertIdentityAllowed, toEmailList, withNormalisedEmail } from '~/core/identities/identities.constants'
import type { Identities } from '~/core/identities/identities.types'
import type { Org } from '~/core/orgs/orgs.types'
import { patchOrNone, stripUndefined } from '~/core/patch'
import { isFiniteNumber } from '~/core/predicates'
import { getProfileString } from '~/core/predicates/predicates'
import { assertSessionAllowed } from '~/core/sessions/sessions.constants'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
import { MEMORY_RAISES, type MemoryFault } from './memory.constants'

/** Every row leaves and enters as a copy: a `Map` hands back a reference, so a caller that mutated a row it
 *  read would rewrite the store with no write issued. `structuredClone` because the nesting is what leaks. */
function copy<T>(row: T): T {
  return structuredClone(row)
}

/** Store a copy and hand back a different copy, so neither side aliases the other. */
function put<T>(map: Map<string, T>, key: string, row: T): T {
  map.set(key, copy(row))
  return copy(row)
}

/** The version moves with it: a revocation that leaves it alone loses to a `rotate` already holding the old
 *  number, which is the race RFC 6749 section 10.4 is about. Every dialect bumps it through its own writer. */
function revoked<T extends { revokedAt: Date | null; updatedAt: Date; version: number }>(row: T): T {
  const now = new Date()
  return row.revokedAt ? row : { ...row, revokedAt: now, updatedAt: now, version: row.version + 1 }
}

/** Every dialect matches on `lower(profile->>'email')`, so a case-sensitive compare here would let memory
 *  hold two live rows for one address and miss the row a caller asked for. */
function sameEmail(a: string | undefined, b: string | undefined): boolean {
  return a !== undefined && b !== undefined && a.toLowerCase() === b.toLowerCase()
}

/** The three unique indexes every SQL dialect carries over these rows. Hidden rows count, none being partial
 *  on `deleted_at`, and `self` is excluded so an update is not refused by its own row. PERF: one pass. */
function assertFree(
  rows: Iterable<{ id: string; profile: unknown; deletedAt: Date | null; providers: Identities.ProviderLink[] }>,
  taking: { profile: unknown; providers: Identities.ProviderLink[] },
  self: string | undefined,
): void {
  const email = getProfileString(taking.profile, 'email')
  const username = getProfileString(taking.profile, 'username')
  // A stolen login is named before a taken address, whichever row holds which, so one pass answers what a
  // pass per login did, rather than letting iteration order decide.
  let taken: AuthError<'AUTH_EMAIL_TAKEN' | 'AUTH_USERNAME_TAKEN'> | null = null
  for (const other of rows) {
    if (other.id === self) continue
    for (const link of taking.providers) {
      if (other.providers.some((p) => p.providerId === link.providerId && p.providerSub === link.providerSub)) {
        throw new AuthError('AUTH_PROVIDER_TAKEN', { providerId: link.providerId })
      }
    }
    if (taken) continue
    if (sameEmail(getProfileString(other.profile, 'email'), email)) taken = new AuthError('AUTH_EMAIL_TAKEN')
    else if (sameEmail(getProfileString(other.profile, 'username'), username)) {
      taken = new AuthError('AUTH_USERNAME_TAKEN')
    }
  }
  if (taken) throw taken
}

/**
 * The credential rules every dialect carries as table constraints, so the unit tier is held to what
 * production enforces rather than to memory's lack of a schema.
 */
function assertCredentialAllowed(
  rows: Iterable<Credential.Me>,
  input: Credential.CreateInput,
  tenantId: string | null,
  createdAt: Date,
): void {
  if (!AUTH_CREDENTIAL_KINDS.includes(input.kind)) {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: `unknown credential kind: ${input.kind}` })
  }
  if (typeof input.secret !== 'string' || input.secret.trim() === '') {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'secret is blank' })
  }
  if (tenantId === '') {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'tenant is blank' })
  }
  if (input.expiresAt !== null && input.expiresAt.getTime() < createdAt.getTime()) {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'expiresAt precedes createdAt' })
  }
  // `PasswordsImpl.set` deletes then creates, so a delete that did not happen would otherwise leave a
  // second row `verify` may pick instead. Revoked rows hold the slot too, as the unique index does.
  if (input.kind !== 'password') return
  for (const row of rows) {
    if (row.kind === 'password' && row.identityId === input.identityId && row.tenantId === tenantId) {
      throw new AuthError('AUTH_ALREADY_EXISTS', { detail: `identity ${input.identityId} already holds a password` })
    }
  }
}

/** How `strict()` recognises a memory store, without reading `constructor.name`. */
type Memory<Store> = Store & { __isMemoryStore: true }

/** In-memory adapter, dev and test only; strict mode rejects it when `env: 'production'`.
 *  One class, as every dialect is: the facets share the maps and the `run` boundary that names what threw. */
export class MemoryAdapter<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  OrgMeta = unknown,
> extends AdapterStore<MemoryFault> {
  constructor() {
    super(MEMORY_RAISES)
  }

  private _identities = new Map<string, Identities.Me<Profile>>()
  private _sessions = new Map<string, Sessions.Me>()
  /** When each identity's sessions were last swept wholesale; read by `sessions.create`. One number per
   *  identity ever revoked, which is bounded by `_identities` in a store that holds everything anyway. */
  private _sessionRevokedAt = new Map<string, number>()
  private _credentials = new Map<string, Credential.Me>()
  private _orgs = new Map<string, Org.Me<OrgMeta>>()
  private _memberships = new Map<string, Org.Membership>()

  /** No ctx, or one with no `tenantId`, sees everything; a named tenant sees only its own rows, so a
   *  global (`tenantId: null`) row is invisible to it, exactly as `eq(tenant_id, $1)` is in SQL. */
  private _inTenant(row: { tenantId: string | null }, ctx: TenantContext | undefined): boolean {
    return ctx?.tenantId === undefined || row.tenantId === ctx.tenantId
  }

  /** Org ids are the host's own and two tenants may use the same one, so the tenant is part of the key.
   *  JSON, not a joined string: an id carrying the separator would otherwise collide with another pair. */
  private _orgKey(tenantId: string | null, orgId: string): string {
    return JSON.stringify([tenantId, orgId])
  }

  private _memberKey(tenantId: string | null, orgId: string, identityId: string): string {
    return JSON.stringify([tenantId, orgId, identityId])
  }

  readonly identities: Memory<Adapter.Me<Profile>['identities']> = {
    find: (by) =>
      this.run(async () => {
        if ('id' in by) {
          const row = this._identities.get(by.id)
          if (!row || isSoftDeleted(row)) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

          return copy(row)
        }
        // Read before the scan, so an empty list is refused whether or not there is a row to compare against.
        const emails = 'email' in by ? toEmailList(by.email) : null
        for (const row of this._identities.values()) {
          if (isSoftDeleted(row)) continue
          const hit = emails
            ? emails.some((e) => sameEmail(getProfileString(row.profile, 'email'), e))
            : 'providerId' in by &&
              row.providers.some((p) => p.providerId === by.providerId && p.providerSub === by.providerSub)
          if (hit) return copy(row)
        }

        throw new AuthError('AUTH_IDENTITY_NOT_FOUND')
      }),

    __isMemoryStore: true,

    create: (raw) =>
      this.run(async () => {
        const input = withNormalisedEmail(raw)
        // Atomic scan closes the race between two concurrent first-oauth-callbacks.
        const providers = (input.providers ?? []).map((l) => ({
          ...l,
          addedAt: l.addedAt ?? new Date(),
          addedBy: actorId(),
        }))
        assertIdentityAllowed({ profile: input.profile, providers })
        assertFree(this._identities.values(), { profile: input.profile, providers }, undefined)

        const now = new Date()
        const row: Identities.Me<Profile> = {
          ...input,
          createdAt: now,
          createdBy: actorId(),
          deletedAt: null,
          deletedBy: null,
          emailVerified: input.emailVerified ?? false,
          id: authUuidV7(),
          providers,
          updatedAt: now,
          updatedBy: actorId(),
          version: 1,
        }

        return put(this._identities, row.id, row)
      }),

    erase: (id) =>
      this.run(async () => {
        // Read before the delete, so the caller still gets the row it removed.
        const cur = this._identities.get(id)
        if (!cur) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')
        this._identities.delete(id)

        // The cascade, by hand: `credentials.findByHashedSecret` never joins back to identities, so a live
        // credential on an erased account would still resolve.
        for (const [key, row] of this._credentials) if (row.identityId === id) this._credentials.delete(key)
        for (const [key, row] of this._sessions) if (row.identityId === id) this._sessions.delete(key)
        for (const [key, row] of this._memberships) if (row.identityId === id) this._memberships.delete(key)

        return copy(cur)
      }),

    /** One pass over each child map for the whole set, not one per id: the cascade is the expensive
     *  half and it does not get cheaper for being run fifty times. */
    eraseMany: (ids) =>
      this.run(async () => {
        const gone: Identities.Me<Profile>[] = []
        const hit = new Set<string>()
        for (const id of ids) {
          const cur = this._identities.get(id)
          if (!cur) continue
          this._identities.delete(id)
          gone.push(copy(cur))
          hit.add(id)
        }
        if (hit.size > 0) {
          for (const [key, row] of this._credentials) if (hit.has(row.identityId)) this._credentials.delete(key)
          for (const [key, row] of this._sessions) {
            if (row.identityId !== null && hit.has(row.identityId)) this._sessions.delete(key)
          }
          for (const [key, row] of this._memberships) if (hit.has(row.identityId)) this._memberships.delete(key)
        }

        return gone
      }),

    /** What makes a soft delete a delete: a window that has closed is past restoring, so the row goes for
     *  real, children and all, exactly as `eraseMany` takes them. */
    gc: (now) =>
      this.run(async () => {
        // The cutoff is the caller's, and every comparison against NaN is false while every one against
        // Infinity is true, so an unusable number does not fail - it sweeps nothing or it sweeps everything,
        // and the dialects disagreed about which.
        if (!isFiniteNumber(now)) {
          throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'gc(now) requires a finite epoch-ms cutoff' })
        }
        const hit = new Set<string>()
        for (const [id, row] of this._identities) {
          if (row.deletedAt != null && row.deletedAt.getTime() < now) {
            this._identities.delete(id)
            hit.add(id)
          }
        }
        if (hit.size === 0) return { deleted: 0 }

        // The cascade, by hand, exactly as `eraseMany` does it.
        for (const [key, row] of this._credentials) if (hit.has(row.identityId)) this._credentials.delete(key)
        for (const [key, row] of this._sessions) {
          if (row.identityId !== null && hit.has(row.identityId)) this._sessions.delete(key)
        }
        for (const [key, row] of this._memberships) if (hit.has(row.identityId)) this._memberships.delete(key)

        return { deleted: hit.size }
      }),

    link: (identityId, link) =>
      this.run(async () => {
        // SECURITY: a hidden row cannot take a new login, as `isNull(deletedAt)` refuses it on every dialect.
        const cur = this._identities.get(identityId)
        if (!cur || isSoftDeleted(cur)) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')
        assertIdentityAllowed({ providers: [link] })

        // SECURITY: hidden rows count as holders, `uq_auth_identity_providers_sub` not being partial.
        for (const [otherId, other] of this._identities) {
          if (otherId === identityId) continue
          if (other.providers.some((p) => p.providerId === link.providerId && p.providerSub === link.providerSub)) {
            throw new AuthError('AUTH_PROVIDER_TAKEN', { providerId: link.providerId })
          }
        }
        // Re-linking a provider this row already holds adds no second entry: a retried OAuth callback is the
        // ordinary way this is reached, and it is what the SQL unique enforces. The version still moves, as
        // on every dialect: the write was accepted.
        if (cur.providers.some((p) => p.providerId === link.providerId)) {
          return put(this._identities, identityId, { ...cur, updatedAt: new Date(), version: cur.version + 1 })
        }

        const added = { ...link, addedAt: link.addedAt ?? new Date(), addedBy: actorId() }

        return put(this._identities, identityId, {
          ...cur,
          providers: [...cur.providers, added],
          updatedAt: new Date(),
          version: cur.version + 1,
        })
      }),

    restore: (id) =>
      this.run(async () => {
        const cur = this._identities.get(id)
        if (!cur) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

        // A live row is handed back untouched, which is what every dialect answers: only a window that
        // has closed is past restoring.
        const deletedAtMs = cur.deletedAt?.getTime()
        if (deletedAtMs === undefined) return copy(cur)
        if (deletedAtMs < Date.now()) throw new AuthError('AUTH_GRACE_EXPIRED')

        // No freeness check: a hidden row held its address, handle and logins the whole time.
        return put(this._identities, id, {
          ...cur,
          deletedAt: null,
          deletedBy: null,
          updatedAt: new Date(),
          version: cur.version + 1,
        })
      }),

    /** The set form over one id. It answers with the rows it hid, so an empty answer is the miss this
     *  raises on. */
    softDelete: (id, gracePeriodMs) =>
      this.run(async () => {
        const [row] = await this.identities.softDeleteMany([id], gracePeriodMs)
        if (!row) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

        return row
      }),

    /** `deletedAt` is when the grace window closes, not when the delete happened. An already-hidden row is
     *  left out of the answer, so re-hiding it reads as a miss and its grace window does not move.
     *  The verified claim does not survive the trip: a restore must re-prove the address.
     *  NOTE: `updatedAt` moves on every write that touches the row, because `$onUpdate` moves it in
     *  every dialect. */
    softDeleteMany: (ids, gracePeriodMs) =>
      this.run(async () => {
        const deletedAt = new Date(Date.now() + gracePeriodMs)
        const updatedAt = new Date()
        const hidden: Identities.Me<Profile>[] = []
        for (const id of ids) {
          const cur = this._identities.get(id)
          if (!cur || isSoftDeleted(cur)) continue
          hidden.push(
            put(this._identities, id, {
              ...cur,
              deletedAt,
              deletedBy: actorId(),
              emailVerified: false,
              updatedAt,
              version: cur.version + 1,
            }),
          )
        }

        return hidden
      }),

    unlink: (identityId, providerId) =>
      this.run(async () => {
        // SECURITY: a hidden row is not reachable, as `isNull(deletedAt)` refuses it on every dialect.
        const cur = this._identities.get(identityId)
        if (!cur || isSoftDeleted(cur)) throw new AuthError('AUTH_IDENTITY_NOT_FOUND')

        const providers = cur.providers.filter((p) => p.providerId !== providerId)

        return put(this._identities, identityId, { ...cur, providers, updatedAt: new Date(), version: cur.version + 1 })
      }),

    update: (id, raw, expectedVersion) =>
      this.run(async () => {
        const patch = withNormalisedEmail(raw)
        const cur = this._identities.get(id)
        // A conditional update matching nothing is a stale write whether the row is gone, hidden or the version
        // moved: a dialect cannot tell those apart from `0 rows affected`, and a retrying caller needs one answer.
        // SECURITY: a hidden row is not reachable.
        if (!cur || isSoftDeleted(cur))
          throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })
        if (cur.version !== expectedVersion) {
          throw new AuthError('AUTH_STALE_WRITE', { actual: cur.version, expected: expectedVersion })
        }
        // A patch that moves the profile clears the same two indexes a dialect checks on the UPDATE.
        if (patch.profile !== undefined) {
          assertIdentityAllowed({ profile: patch.profile })
          assertFree(this._identities.values(), { profile: patch.profile, providers: [] }, id)
        }

        return put(this._identities, id, {
          ...cur,
          ...stripUndefined(patch),
          updatedAt: new Date(),
          // `createdBy` comes through the spread: it belongs to whoever made the row.
          updatedBy: actorId(),
          version: cur.version + 1,
        })
      }),
  }

  readonly sessions: Memory<Adapter.Me<Profile>['sessions']> = {
    __isMemoryStore: true,

    create: (s) =>
      this.run(async () => {
        // SECURITY: the id is the token hash the caller computed, so a repeat is a collision, not an
        // update. Every dialect's primary key refuses it; overwriting would hand the old token the new row.
        if (this._sessions.has(s.id)) throw new AuthError('AUTH_ALREADY_EXISTS')
        assertSessionAllowed(s)
        // SECURITY: a session minted before this identity's last revoke does not survive it, as in
        // redis. `AUTH_STALE_WRITE` rather than `AUTH_SESSION_REVOKED`, which the reader's absent set
        // would swallow as "no session" instead of the lost race it is.
        const revokedAt = s.identityId ? this._sessionRevokedAt.get(s.identityId) : undefined
        if (revokedAt !== undefined && s.createdAt.getTime() < revokedAt) {
          throw new AuthError('AUTH_STALE_WRITE', { actual: revokedAt, expected: s.createdAt.getTime() })
        }

        // Fill the nullable columns the caller omitted, so the store holds a complete row.
        put(this._sessions, s.id, {
          aal: s.aal,
          absoluteExpiresAt: s.absoluteExpiresAt,
          actingAs: s.actingAs ?? null,
          createdAt: s.createdAt,
          csrfHash: s.csrfHash ?? null,
          expiresAt: s.expiresAt,
          factors: s.factors,
          fingerprint: s.fingerprint ?? null,
          fresh: s.fresh,
          id: s.id,
          identityId: s.identityId,
          ip: s.ip ?? null,
          kind: s.kind,
          rotatedAt: s.rotatedAt,
          tenantId: s.tenantId ?? null,
          updatedAt: s.updatedAt,
          userAgent: s.userAgent ?? null,
        })
      }),

    delete: (id) =>
      this.run(async () => {
        this._sessions.delete(id)
      }),

    /** One pass for the whole set, rather than one pass per identity. */
    deleteAllForIdentities: (identityIds) =>
      this.run(async () => {
        const wanted = new Set(identityIds)
        const now = Date.now()
        for (const identityId of wanted) this._sessionRevokedAt.set(identityId, now)
        const gone: Sessions.Revoked[] = []
        for (const s of this._sessions.values()) {
          if (s.identityId === null || !wanted.has(s.identityId)) continue
          gone.push({ id: s.id, identityId: s.identityId })
          this._sessions.delete(s.id)
        }

        return gone
      }),

    deleteAllForIdentity: (identityId, ctx?) =>
      this.run(async () => {
        // Identity-wide even on a scoped sweep, as in redis: the racing create is refused and retried
        // rather than being let through because it named a different tenant.
        this._sessionRevokedAt.set(identityId, Date.now())
        for (const s of this._sessions.values()) {
          if (s.identityId === identityId && this._inTenant(s, ctx)) this._sessions.delete(s.id)
        }
      }),

    deleteMany: (ids) =>
      this.run(async () => {
        const gone: Sessions.Revoked[] = []
        for (const id of ids) {
          const row = this._sessions.get(id)
          if (!row) continue
          this._sessions.delete(id)
          gone.push({ id, identityId: row.identityId })
        }

        return gone
      }),

    gc: (now) =>
      this.run(async () => {
        // The cutoff is the caller's, and every comparison against NaN is false while every one against
        // Infinity is true, so an unusable number does not fail - it sweeps nothing or it sweeps everything,
        // and the dialects disagreed about which.
        if (!isFiniteNumber(now)) {
          throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'gc(now) requires a finite epoch-ms cutoff' })
        }
        let deleted = 0
        for (const s of this._sessions.values()) {
          if (s.expiresAt.getTime() < now || s.absoluteExpiresAt.getTime() < now) {
            this._sessions.delete(s.id)
            deleted++
          }
        }

        return { deleted }
      }),

    getByHash: (sidHash) =>
      this.run(async () => {
        const row = this._sessions.get(sidHash)
        if (!row) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${sidHash} not found` })

        return copy(row)
      }),

    listByIdentity: (identityId, ctx?) =>
      this.run(async () =>
        [...this._sessions.values()].filter((s) => s.identityId === identityId && this._inTenant(s, ctx)).map(copy),
      ),

    update: (id, patch, expectedUpdatedAt) =>
      this.run(async () => {
        const cur = this._sessions.get(id)
        // Redis and SQL both surface a missing row as AUTH_SESSION_REVOKED; keep memory in step.
        if (!cur) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })
        if (expectedUpdatedAt !== undefined && cur.updatedAt.getTime() !== expectedUpdatedAt.getTime()) {
          throw new AuthError('AUTH_STALE_WRITE', {
            actual: cur.updatedAt.getTime(),
            expected: expectedUpdatedAt.getTime(),
          })
        }

        // No implicit `rotatedAt` stamp: moving it on every patch would mask an expired gate. `id` is
        // pinned because the key is the sid hash the cookie carries.
        // `updatedAt` is stamped here rather than taken from the patch, as `$onUpdate` does in SQL, and is
        // strictly increasing: it is the token `expectedUpdatedAt` compares, and `Date` resolves to the
        // millisecond, so two writes inside one would stamp equal and the second land on top of the first.
        const next: Sessions.Me = {
          ...cur,
          ...stripUndefined(patch),
          id: cur.id,
          updatedAt: new Date(Math.max(Date.now(), cur.updatedAt.getTime() + 1)),
        }
        assertSessionAllowed(next)

        return put(this._sessions, id, next)
      }),
  }

  readonly credentials: Memory<Adapter.Me<Profile>['credentials']> = {
    __isMemoryStore: true,

    delete: (id, ctx) =>
      this.run(async () => {
        // Read before the delete: this is the caller's last look at the row.
        const cur = this._credentials.get(id)
        if (!cur || !this._inTenant(cur, ctx)) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
        this._credentials.delete(id)

        return copy(cur)
      }),

    deleteByKind: (identityId, kind, ctx) =>
      this.run(async () => {
        const removed: Credential.Me[] = []
        for (const row of this._credentials.values()) {
          if (row.identityId === identityId && row.kind === kind && this._inTenant(row, ctx)) {
            removed.push(copy(row))
            this._credentials.delete(row.id)
          }
        }

        return removed
      }),

    deleteByKindAndPurpose: (identityId, kind, purpose, ctx) =>
      this.run(async () => {
        const removed: Credential.Me[] = []
        for (const row of this._credentials.values()) {
          if (row.identityId !== identityId || row.kind !== kind || !this._inTenant(row, ctx)) continue
          if (getCredentialPurpose(row) !== purpose) continue
          removed.push(copy(row))
          this._credentials.delete(row.id)
        }

        return removed
      }),

    findByHashedSecret: (secretHash, kind, ctx) =>
      this.run(async () => {
        // Freshest live first, falling back to revoked. `timingSafeEqual` defeats hash oracles.
        let live: Credential.Me | null = null
        let revoked: Credential.Me | null = null
        for (const row of this._credentials.values()) {
          if (row.kind !== kind) continue
          if (!timingSafeEqual(row.secret, secretHash)) continue
          if (!this._inTenant(row, ctx)) continue

          const createdMs = row.createdAt.getTime()
          if (isRevoked(row)) {
            if (!revoked || createdMs > revoked.createdAt.getTime()) revoked = row
          } else if (!live || createdMs > live.createdAt.getTime()) {
            live = row
          }
        }
        const found = live ?? revoked
        if (!found) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return copy(found)
      }),

    findById: (id, ctx) =>
      this.run(async () => {
        const row = this._credentials.get(id)
        if (!row || !this._inTenant(row, ctx)) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return copy(row)
      }),

    // Newest first, id breaking a same-millisecond tie, as every dialect orders it: callers take the
    // first live row, and `mfa.confirm` reaching the oldest enrollment instead of the newest is what
    // insertion order costs.
    listByIdentity: (identityId, kind, ctx) =>
      this.run(async () =>
        [...this._credentials.values()]
          .filter((c) => c.identityId === identityId && (kind == null || c.kind === kind) && this._inTenant(c, ctx))
          .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime() || b.id.localeCompare(a.id))
          .map(copy),
      ),

    patchMetadata: (id, patch, ctx, expectedVersion) =>
      this.run(async () => {
        const cur = this._credentials.get(id)
        // Not there, or not this tenant's: 404, the same answer the SQL path's read gives before it writes.
        // `AUTH_STALE_WRITE` would tell the caller to retry a row that is never coming back - unless the
        // caller asked for a version, where the dialects' conditional UPDATE cannot tell the two apart.
        if (!cur || !this._inTenant(cur, ctx)) {
          if (expectedVersion !== undefined) {
            throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })
          }
          throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
        }
        if (expectedVersion !== undefined && cur.version !== expectedVersion) {
          throw new AuthError('AUTH_STALE_WRITE', { actual: cur.version, expected: expectedVersion })
        }

        // A patch saying nothing leaves the column alone, so a NULL metadata does not become `{}`.
        const kept = patchOrNone(patch)

        return put(this._credentials, id, {
          ...cur,
          metadata: kept ? { ...(cur.metadata ?? {}), ...kept } : cur.metadata,
          updatedAt: new Date(),
          version: cur.version + 1,
        })
      }),

    revoke: (id, ctx) =>
      this.run(async () => {
        const cur = this._credentials.get(id)
        if (!cur || !this._inTenant(cur, ctx)) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        return put(this._credentials, id, revoked(cur))
      }),

    /** Memory walks every row, where a dialect indexes the familyId out of the metadata column. */
    revokeFamily: (familyId, ctx) =>
      this.run(async () => {
        let moved = 0
        for (const row of this._credentials.values()) {
          if (row.kind !== 'oauth' || row.revokedAt || !this._inTenant(row, ctx)) continue
          if (row.metadata?.familyId !== familyId) continue
          this._credentials.set(row.id, copy({ ...revoked(row), updatedBy: actorId() }))
          moved += 1
        }

        return moved
      }),

    rotate: (id, newSecret, expectedVersion, ctx) =>
      this.run(async () => {
        const cur = this._credentials.get(id)
        // Out of tenant is indistinguishable from gone, and both are stale writes: the conditional UPDATE
        // the dialects issue matches no row either way and reports `0 rows affected`.
        if (!cur || !this._inTenant(cur, ctx)) {
          throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })
        }
        if (cur.version !== expectedVersion) {
          throw new AuthError('AUTH_STALE_WRITE', { actual: cur.version, expected: expectedVersion })
        }

        return put(this._credentials, id, {
          ...cur,
          // NOTE: a rotation is a use, so it stamps lastUsedAt, as every dialect does.
          lastUsedAt: new Date(),
          secret: newSecret,
          updatedAt: new Date(),
          version: cur.version + 1,
        })
      }),

    create: (input, ctx) =>
      this.run(async () => {
        const id = authUuidV7()
        const createdAt = new Date()
        const tenantId = input.tenantId ?? ctx?.tenantId ?? null
        assertCredentialAllowed(this._credentials.values(), input, tenantId, createdAt)

        return put(this._credentials, id, {
          createdAt,
          createdBy: actorId(),
          expiresAt: input.expiresAt ?? null,
          id,
          identityId: input.identityId,
          kind: input.kind,
          lastUsedAt: input.lastUsedAt ?? null,
          metadata: input.metadata ?? null,
          revokedAt: input.revokedAt ?? null,
          secret: input.secret,
          tenantId,
          updatedAt: createdAt,
          updatedBy: actorId(),
          version: 1,
        })
      }),
  }

  readonly orgs: Memory<Org.Store<OrgMeta>> = {
    __isMemoryStore: true,

    addMember: (m, ctx) =>
      this.run(async () => {
        // The row carries its own tenant and the context names one, so the two can disagree. The facet
        // stamps it from the context and cannot, but the store is called directly for bulk admin work -
        // which is the path `orgs-toctou-add-member.test.ts` exists for - and there the write would land
        // in whichever tenant the row named.
        // Written out rather than through `_inTenant`, so `asked` narrows to a string without a cast.
        if (ctx.tenantId !== undefined && m.tenantId !== ctx.tenantId) {
          throw new AuthError('AUTH_TENANT_SCOPE_VIOLATION', { asked: ctx.tenantId, got: m.tenantId })
        }
        const key = this._memberKey(m.tenantId, m.orgId, m.identityId)
        const cur = this._memberships.get(key)
        if (cur && cur.leftAt === null) {
          throw new AuthError('AUTH_ALREADY_EXISTS', { detail: 'identity already a member of this org' })
        }
        // A stub on first membership, so the reads stay consistent with the writes.
        const orgKey = this._orgKey(m.tenantId, m.orgId)
        if (!this._orgs.has(orgKey)) {
          this._orgs.set(orgKey, {
            createdAt: new Date(),
            domain: null,
            id: m.orgId,
            metadata: null,
            name: m.orgId,
            tenantId: m.tenantId,
          })
        }

        return put(this._memberships, key, { ...m, invitedAt: m.invitedAt ?? null, joinedAt: new Date(), leftAt: null })
      }),

    getOrg: (id, ctx) =>
      this.run(async () => {
        // Scanned rather than keyed, because a ctx naming no tenant sees every row and a keyed lookup
        // would need the tenant it is not being told.
        const org = [...this._orgs.values()].find((o) => o.id === id && this._inTenant(o, ctx))
        if (!org) throw new AuthError('AUTH_ORG_NOT_FOUND')

        return copy(org)
      }),

    listMembers: (orgId, ctx) =>
      this.run(async () =>
        [...this._memberships.values()]
          .filter((m) => m.orgId === orgId && !m.leftAt && this._inTenant(m, ctx))
          .map(copy),
      ),

    listOrgsForIdentity: (identityId, ctx) =>
      this.run(async () => {
        const seen = new Set<string>()
        const out: Org.Me<OrgMeta>[] = []
        for (const m of this._memberships.values()) {
          if (m.identityId !== identityId || m.leftAt || !this._inTenant(m, ctx)) continue
          const key = this._orgKey(m.tenantId, m.orgId)
          if (seen.has(key)) continue
          seen.add(key)
          const org = this._orgs.get(key)
          if (org) out.push(copy(org))
        }

        return out
      }),

    removeMember: (orgId, identityId, ctx) =>
      this.run(async () => {
        const key = this._memberKey(ctx.tenantId ?? null, orgId, identityId)
        const cur = this._memberships.get(key)
        if (!cur || !this._inTenant(cur, ctx)) throw new AuthError('AUTH_MEMBERSHIP_NOT_FOUND')

        return put(this._memberships, key, { ...cur, leftAt: cur.leftAt ?? new Date() })
      }),

    setRoles: (orgId, identityId, roles, ctx) =>
      this.run(async () => {
        const key = this._memberKey(ctx.tenantId ?? null, orgId, identityId)
        const cur = this._memberships.get(key)
        if (!cur || !this._inTenant(cur, ctx)) throw new AuthError('AUTH_MEMBERSHIP_NOT_FOUND')

        return put(this._memberships, key, { ...cur, roles: [...roles] })
      }),
  }

  /** Register an org row so `getOrg` and `listOrgsForIdentity` answer. NOTE: `Org.Store` is a read
   *  interface over the host app's own tables, so there is no `createOrg` to call. */
  seedOrg(org: Org.Me<OrgMeta>): Org.Me<OrgMeta> {
    return put(this._orgs, this._orgKey(org.tenantId, org.id), org)
  }

  /** The stored rows themselves, for tests only. NOTE: copying on the way in and out removes the only way
   *  a test had to plant a row no store API would produce, which is what the fail-closed tests need. */
  get raw(): {
    credentials: Map<string, Credential.Me>
    identities: Map<string, Identities.Me<Profile>>
    memberships: Map<string, Org.Membership>
    orgs: Map<string, Org.Me<OrgMeta>>
    sessions: Map<string, Sessions.Me>
  } {
    return {
      credentials: this._credentials,
      identities: this._identities,
      memberships: this._memberships,
      orgs: this._orgs,
      sessions: this._sessions,
    }
  }
}

/** In-process adapter holding every store in memory. For tests and local runs; nothing survives a restart. */
export function memoryAdapter<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  OrgMeta = unknown,
>(): MemoryAdapter<Profile, OrgMeta> {
  return new MemoryAdapter()
}
