import { type Adapter, AdapterStore } from '~/adapters/adapter'
import { actorId } from '~/core/actor'
import { outcomesFromAffected } from '~/core/batch'
import { getCredentialPurpose, getProfileString, isRevoked, isSoftDeleted } from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { randomToken, timingSafeEqual } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import { toEmailList, withNormalisedEmail } from '~/core/identities/identities.constants'
import type { Identities } from '~/core/identities/identities.types'
import type { Org } from '~/core/orgs/orgs.types'
import { patchOrNone, stripUndefined } from '~/core/patch'
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
function revoked<T extends { revokedAt: Date | null; version: number }>(row: T): T {
  return row.revokedAt ? row : { ...row, revokedAt: new Date(), version: row.version + 1 }
}

/** Every dialect matches on `lower(profile->>'email')`, so a case-sensitive compare here would let memory
 *  hold two live rows for one address and miss the row a caller asked for. */
function sameEmail(a: string | undefined, b: string | undefined): boolean {
  return a !== undefined && b !== undefined && a.toLowerCase() === b.toLowerCase()
}

/** The three unique indexes every SQL dialect carries over these rows. Hidden rows count - none is partial
 *  on `deleted_at` - and `self` is excluded so an update is not refused by its own row. PERF: one pass. */
function assertFree(
  rows: Iterable<{ id: string; profile: unknown; deletedAt: Date | null; providers: Identities.ProviderLink[] }>,
  taking: { profile: unknown; providers: Identities.ProviderLink[] },
  self: string | undefined,
): void {
  const email = getProfileString(taking.profile, 'email')
  const username = getProfileString(taking.profile, 'username')
  // A stolen login is named before a taken address, whichever row holds which - so one pass answers what a
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

/** How `strict()` recognises a memory store, without reading `constructor.name`. */
type Memory<Store> = Store & { __isMemoryStore: true }

/** In-memory adapter - dev + test only; strict mode rejects it when `env: 'production'`.
 *  One class, as every dialect is: the facets share the maps and the `run` boundary that attaches `wrap`. */
export class MemoryAdapter<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  OrgMeta = unknown,
> extends AdapterStore<MemoryFault> {
  constructor() {
    super(MEMORY_RAISES)
  }

  private _identities = new Map<string, Identities.Me<Profile>>()
  private _sessions = new Map<string, Sessions.Me>()
  private _credentials = new Map<string, Credential.Me>()
  private _orgs = new Map<string, Org.Me<OrgMeta>>()
  private _memberships = new Map<string, Org.Membership>()

  /** No ctx, or one with no `tenantId`, sees everything; a named tenant sees only its own rows, so a
   *  global (`tenantId: null`) row is invisible to it, exactly as `eq(tenant_id, $1)` is in SQL. */
  private _inTenant(row: { tenantId: string | null }, ctx: TenantContext | undefined): boolean {
    return ctx?.tenantId === undefined || row.tenantId === ctx.tenantId
  }

  readonly identities: Memory<Adapter.Wrapped<Adapter.Me<Profile>['identities'], MemoryFault>> = {
    find: (by) =>
      this.run(async () => {
        if ('id' in by) {
          const row = this._identities.get(by.id)

          return !row || isSoftDeleted(row) ? null : copy(row)
        }
        // Read before the scan, so an empty list is refused whether or not there is a row to compare
        // it against - a store with nothing in it must not answer differently from a full one.
        const emails = 'email' in by ? toEmailList(by.email) : null
        for (const row of this._identities.values()) {
          if (isSoftDeleted(row)) continue
          const hit = emails
            ? emails.some((e) => sameEmail(getProfileString(row.profile, 'email'), e))
            : 'providerId' in by &&
              row.providers.some((p) => p.providerId === by.providerId && p.providerSub === by.providerSub)
          if (hit) return copy(row)
        }

        return null
      }),

    __isMemoryStore: true,

    create: (raw) =>
      this.run(async () => {
        const input = withNormalisedEmail(raw)
        // Atomic scan closes the race between two concurrent first-oauth-callbacks.
        const providers = (input.providers ?? []).map((l) => ({ ...l, addedAt: l.addedAt ?? new Date() }))
        assertFree(this._identities.values(), { profile: input.profile, providers }, undefined)

        const now = new Date()
        const row: Identities.Me<Profile> = {
          ...input,
          createdAt: now,
          createdBy: actorId(),
          deletedAt: null,
          deletedBy: null,
          // New identities are unverified unless the caller states otherwise.
          emailVerified: input.emailVerified ?? false,
          id: randomToken(16),
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
        const cur = this._identities.get(id) ?? null
        this._identities.delete(id)

        // The cascade, by hand. Without it a hard-deleted account kept live credentials, and
        // `credentials.findByHashedSecret` never joins back to identities, so its API keys kept resolving.
        for (const [key, row] of this._credentials) if (row.identityId === id) this._credentials.delete(key)
        for (const [key, row] of this._sessions) if (row.identityId === id) this._sessions.delete(key)
        for (const [key, row] of this._memberships) if (row.identityId === id) this._memberships.delete(key)

        return cur ? copy(cur) : null
      }),

    link: (identityId, link) =>
      this.run(async () => {
        const cur = this._identities.get(identityId)
        if (!cur) return null

        // SECURITY: closes the TOCTOU window in `findByProviderSub` -> `link`. Hidden rows count, as
        // `uq_auth_identity_providers_sub` is not partial - the same code the dialects map that unique to.
        for (const [otherId, other] of this._identities) {
          if (otherId === identityId) continue
          if (other.providers.some((p) => p.providerId === link.providerId && p.providerSub === link.providerSub)) {
            throw new AuthError('AUTH_PROVIDER_TAKEN', { providerId: link.providerId })
          }
        }
        // Re-linking a provider this row already holds is a no-op, not a second entry: a retried OAuth
        // callback is the ordinary way this is reached, and it is what the SQL unique enforces.
        if (cur.providers.some((p) => p.providerId === link.providerId)) return copy(cur)

        const added = { ...link, addedAt: link.addedAt ?? new Date() }

        return put(this._identities, identityId, { ...cur, providers: [...cur.providers, added] })
      }),

    merge: (survivorId, dupId) =>
      this.run(async () => {
        const survivor = this._identities.get(survivorId)
        if (!survivor) return null
        // Merging a row into itself would otherwise delete it: the loops run, then `delete(dupId)` removes
        // the survivor and the caller is handed a row that is no longer in the store.
        if (survivorId === dupId) return copy(survivor)

        const dup = this._identities.get(dupId)
        if (!dup) return null

        // A duplicate usually exists *because* it signed in through the same provider, so concatenating
        // unfiltered produced two links sharing a `providerId`, which no unique index would have permitted.
        const providers = [...survivor.providers]
        for (const link of dup.providers) {
          if (providers.some((p) => p.providerId === link.providerId)) continue
          providers.push(link)
        }
        const merged: Identities.Me<Profile> = { ...survivor, providers }
        put(this._identities, survivorId, merged)

        for (const row of this._credentials.values()) {
          if (row.identityId === dupId) this._credentials.set(row.id, copy({ ...row, identityId: survivorId }))
        }
        // Sessions were the omission that mattered: the dup's live sessions kept pointing at an id that no
        // longer resolves, so the merged-away account stayed signed in with no way to sign it out.
        for (const [key, row] of this._sessions) {
          if (row.identityId === dupId) this._sessions.set(key, copy({ ...row, identityId: survivorId }))
        }
        for (const [key, m] of this._memberships) {
          if (m.identityId !== dupId) continue
          this._memberships.delete(key)

          // Both accounts in the same org: keep the survivor's own membership and union the roles onto it.
          // Overwriting was a silent privilege change in whichever direction the iteration happened to run.
          const survivorKey = `${m.orgId}:${survivorId}`
          const existing = this._memberships.get(survivorKey)
          this._memberships.set(
            survivorKey,
            copy(
              existing
                ? { ...existing, roles: [...new Set([...existing.roles, ...m.roles])] }
                : { ...m, identityId: survivorId },
            ),
          )
        }
        this._identities.delete(dupId)

        return copy(merged)
      }),

    restore: (id) =>
      this.run(async () => {
        // No such row is `null`, matching `softDelete` and `erase`; a refusal throws, naming the rule.
        const cur = this._identities.get(id)
        if (!cur) return null

        const deletedAtMs = cur.deletedAt?.getTime()
        if (!deletedAtMs || deletedAtMs < Date.now()) throw new AuthError('AUTH_GRACE_EXPIRED')

        // No freeness check: the row held its address, handle and logins the whole time it was hidden, so
        // there is nothing for a live row to have taken. Restore only makes it visible again.
        return put(this._identities, id, { ...cur, deletedAt: null, deletedBy: null, updatedAt: new Date() })
      }),

    softDelete: (id, gracePeriodMs) =>
      this.run(async () => {
        const cur = this._identities.get(id)
        // Already hidden: `null` matches the set-based form, and stops a second call pushing the grace
        // window forward on a row that was already eligible for purge.
        if (!cur || isSoftDeleted(cur)) return null

        // The verified claim does not survive the trip: a restore months later must re-prove the address.
        // NOTE: `updatedAt` moves here and on `restore`, because `$onUpdate` moves it in every dialect.
        return put(this._identities, id, {
          ...cur,
          deletedAt: new Date(Date.now() + gracePeriodMs),
          deletedBy: actorId(),
          emailVerified: false,
          updatedAt: new Date(),
        })
      }),

    unlink: (identityId, providerId) =>
      this.run(async () => {
        const cur = this._identities.get(identityId)
        if (!cur) return null

        const providers = cur.providers.filter((p) => p.providerId !== providerId)

        return put(this._identities, identityId, { ...cur, providers })
      }),

    update: (id, raw, expectedVersion) =>
      this.run(async () => {
        const patch = withNormalisedEmail(raw)
        const cur = this._identities.get(id)
        // A conditional update matching nothing is a stale write whether the row is gone or the version
        // moved: a dialect cannot tell those apart from `0 rows affected`, and a retrying caller needs one answer.
        if (!cur) throw new AuthError('AUTH_STALE_WRITE', { actual: -1, expected: expectedVersion })
        if (cur.version !== expectedVersion) {
          throw new AuthError('AUTH_STALE_WRITE', { actual: cur.version, expected: expectedVersion })
        }
        // A patch that moves the profile clears the same two indexes a dialect checks on the UPDATE.
        if (patch.profile !== undefined) {
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

  readonly sessions: Memory<Adapter.Wrapped<Adapter.Me<Profile>['sessions'], MemoryFault>> = {
    __isMemoryStore: true,

    create: (s) =>
      this.run(async () => {
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
        const hit = new Set<string>()
        for (const s of this._sessions.values()) {
          if (s.identityId === null || !wanted.has(s.identityId)) continue
          hit.add(s.identityId)
          this._sessions.delete(s.id)
        }

        return outcomesFromAffected(identityIds, hit)
      }),

    deleteAllForIdentity: (identityId, ctx?) =>
      this.run(async () => {
        for (const s of this._sessions.values()) {
          if (s.identityId === identityId && this._inTenant(s, ctx)) this._sessions.delete(s.id)
        }
      }),

    deleteMany: (ids) =>
      this.run(async () => {
        const hit = new Set<string>()
        for (const id of ids) if (this._sessions.delete(id)) hit.add(id)

        return outcomesFromAffected(ids, hit)
      }),

    gc: (now) =>
      this.run(async () => {
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

        return row ? copy(row) : null
      }),

    listByIdentities: (identityIds) =>
      this.run(async () => {
        const wanted = new Set(identityIds)

        return [...this._sessions.values()].filter((s) => s.identityId !== null && wanted.has(s.identityId)).map(copy)
      }),

    listByIdentity: (identityId, ctx?) =>
      this.run(async () =>
        [...this._sessions.values()].filter((s) => s.identityId === identityId && this._inTenant(s, ctx)).map(copy),
      ),

    update: (id, patch) =>
      this.run(async () => {
        const cur = this._sessions.get(id)
        // Redis and SQL both surface a missing row as AUTH_SESSION_REVOKED; keep memory in step.
        if (!cur) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })

        // No implicit `rotatedAt` stamp: moving it on every patch would mask an expired gate. `id` is pinned
        // because the key is the sid hash the cookie carries.
        return put(this._sessions, id, { ...cur, ...stripUndefined(patch), id: cur.id })
      }),
  }

  readonly credentials: Memory<Adapter.Wrapped<Adapter.Me<Profile>['credentials'], MemoryFault>> = {
    __isMemoryStore: true,

    delete: (id, ctx) =>
      this.run(async () => {
        // Read before the delete: this is the caller's last look at the row.
        const cur = this._credentials.get(id)
        if (!cur || !this._inTenant(cur, ctx)) return null
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

        return found ? copy(found) : null
      }),

    findById: (id, ctx) =>
      this.run(async () => {
        const row = this._credentials.get(id)

        return row && this._inTenant(row, ctx) ? copy(row) : null
      }),

    findByProviderSub: (provider, sub, ctx) =>
      this.run(async () => {
        for (const row of this._credentials.values()) {
          if (row.kind !== 'oauth' || !this._inTenant(row, ctx)) continue
          if (row.metadata?.provider === provider && row.metadata?.sub === sub) return copy(row)
        }

        return null
      }),

    listByIdentity: (identityId, kind, ctx) =>
      this.run(async () =>
        [...this._credentials.values()]
          .filter((c) => c.identityId === identityId && (kind == null || c.kind === kind) && this._inTenant(c, ctx))
          .map(copy),
      ),

    patchMetadata: (id, patch, ctx) =>
      this.run(async () => {
        const cur = this._credentials.get(id)
        // Not there, or not this tenant's: 404, the same answer the SQL path's read gives before it writes.
        // `AUTH_STALE_WRITE` would tell the caller to retry a row that is never coming back.
        if (!cur || !this._inTenant(cur, ctx)) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

        // A patch saying nothing leaves the column alone, so a NULL metadata does not become `{}`.
        const kept = patchOrNone(patch)

        return put(this._credentials, id, {
          ...cur,
          metadata: kept ? { ...(cur.metadata ?? {}), ...kept } : cur.metadata,
          version: cur.version + 1,
        })
      }),

    revoke: (id, ctx) =>
      this.run(async () => {
        const cur = this._credentials.get(id)
        if (!cur || !this._inTenant(cur, ctx)) return null

        return put(this._credentials, id, revoked(cur))
      }),

    /** Memory walks every row, where a dialect indexes the familyId out of the metadata column. */
    revokeFamily: (familyId, ctx) =>
      this.run(async () => {
        let moved = 0
        for (const row of this._credentials.values()) {
          if (row.kind !== 'oauth' || row.revokedAt || !this._inTenant(row, ctx)) continue
          if (row.metadata?.familyId !== familyId) continue
          this._credentials.set(row.id, copy(revoked(row)))
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
          // A rotation is a use, stamped on the same write as in every dialect; without it memory reported
          // a credential as never used after its secret changed, which is what an idle reaper reads.
          lastUsedAt: new Date(),
          secret: newSecret,
          version: cur.version + 1,
        })
      }),

    upsert: (input, ctx) =>
      this.run(async () => {
        const id = randomToken(16)

        return put(this._credentials, id, {
          createdAt: new Date(),
          createdBy: actorId(),
          expiresAt: input.expiresAt ?? null,
          id,
          identityId: input.identityId,
          kind: input.kind,
          lastUsedAt: input.lastUsedAt ?? null,
          metadata: input.metadata ?? null,
          revokedAt: input.revokedAt ?? null,
          secret: input.secret,
          // Inherited from the ctx when the input does not name one.
          tenantId: input.tenantId ?? ctx?.tenantId ?? null,
          updatedBy: actorId(),
          version: 1,
        })
      }),
  }

  readonly orgs: Memory<Adapter.Wrapped<Org.Store<OrgMeta>, MemoryFault>> = {
    __isMemoryStore: true,

    addMember: (m, _ctx?) =>
      this.run(async () => {
        const key = `${m.orgId}:${m.identityId}`
        const cur = this._memberships.get(key)
        if (cur && cur.leftAt === null) {
          throw new AuthError('AUTH_ALREADY_EXISTS', { detail: 'identity already a member of this org' })
        }
        // `Org.Store` has no `createOrg` - orgs live in the host app's tables - which left `_orgs` with no
        // writer, so a stub on first membership keeps the reads consistent with the writes.
        if (!this._orgs.has(m.orgId)) {
          this._orgs.set(m.orgId, { createdAt: new Date(), domain: null, id: m.orgId, metadata: null, name: m.orgId })
        }

        return put(this._memberships, key, { ...m, invitedAt: m.invitedAt ?? null, joinedAt: new Date(), leftAt: null })
      }),

    getOrg: (id, _ctx?) =>
      this.run(async () => {
        const org = this._orgs.get(id)

        return org ? copy(org) : null
      }),

    listMembers: (orgId, _ctx?) =>
      this.run(async () => [...this._memberships.values()].filter((m) => m.orgId === orgId && !m.leftAt).map(copy)),

    listOrgsForIdentity: (identityId, _ctx?) =>
      this.run(async () => {
        const orgIds = new Set<string>()
        for (const m of this._memberships.values()) if (m.identityId === identityId && !m.leftAt) orgIds.add(m.orgId)

        return [...orgIds]
          .map((id) => this._orgs.get(id))
          .filter((org): org is Org.Me<OrgMeta> => Boolean(org))
          .map(copy)
      }),

    removeMember: (orgId, identityId, _ctx?) =>
      this.run(async () => {
        const key = `${orgId}:${identityId}`
        const cur = this._memberships.get(key)
        if (!cur) return null

        return put(this._memberships, key, { ...cur, leftAt: cur.leftAt ?? new Date() })
      }),

    setRoles: (orgId, identityId, roles, _ctx?) =>
      this.run(async () => {
        const key = `${orgId}:${identityId}`
        const cur = this._memberships.get(key)
        if (!cur) return null

        return put(this._memberships, key, { ...cur, roles: [...roles] })
      }),
  }

  /** Register an org row so `getOrg` and `listOrgsForIdentity` answer. NOTE: `Org.Store` is a read
   *  interface over the host app's own tables, so there is no `createOrg` to call. */
  seedOrg(org: Org.Me<OrgMeta>): Org.Me<OrgMeta> {
    return put(this._orgs, org.id, org)
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

/** Factory around {@link MemoryAdapter} for functional-style config. */
export function memoryAdapter<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  OrgMeta = unknown,
>(): MemoryAdapter<Profile, OrgMeta> {
  return new MemoryAdapter()
}

/** The in-memory `{ identities, sessions, credentials }` triple the engine binds. Dev / test only. */
export function memoryStorage<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(): Pick<
  MemoryAdapter<Profile>,
  'credentials' | 'identities' | 'sessions'
> {
  const adapter = new MemoryAdapter<Profile>()

  return { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions }
}
