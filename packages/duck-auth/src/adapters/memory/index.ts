import { getProfileString, isRevoked, isSoftDeleted } from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { randomToken, timingSafeEqual } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import type { Org } from '~/core/orgs/orgs.types'
import { stripUndefined } from '~/core/patch'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { TenantContext } from '~/core/tenant/tenant.types'

/**
 * Every row leaves and enters this adapter as a copy. A `Map` hands back a
 * reference, so without this a caller that mutated a row it read - or that kept
 * hold of the object it passed to `create` - would rewrite the store with no
 * write ever issued, while a real database hands back a fresh row every time.
 * That gap mattered more than it looks: this adapter is what the shared
 * store-compliance suite validates the SQL dialects against, so anything it
 * allowed was a contract the suite could never catch.
 *
 * `structuredClone` rather than a spread because the nesting is what leaks -
 * `providers`, `factors`, `actingAs` and `metadata` are all reachable - and it
 * preserves the `Date`s every row carries, which `JSON.parse(JSON.stringify())`
 * would flatten to strings.
 */
const copy = <T>(row: T): T => structuredClone(row)

/** Store a copy and hand back a different copy, so neither side aliases the other. */
function put<T>(map: Map<string, T>, key: string, row: T): T {
  map.set(key, copy(row))
  return copy(row)
}

/**
 * Emails compare case-insensitively. Every dialect matches on
 * `lower(profile->>'email')` and enforces its unique index the same way, so a
 * case-sensitive compare here let memory hold two live rows for one address and
 * miss the row a caller asked for.
 */
const sameEmail = (a: string | undefined, b: string | undefined): boolean =>
  a !== undefined && b !== undefined && a.toLowerCase() === b.toLowerCase()

/**
 * In-memory adapter - dev + test only. Production must use redis/drizzle/prisma.
 * Strict mode rejects this adapter when `env: 'production'`.
 *
 * Multi-tenant: tenantId filters every query so tests can verify isolation.
 */
export class MemoryAdapter<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  OrgMeta = unknown,
> {
  readonly identities: Identities.Store<Profile>
  readonly sessions: Sessions.Store
  readonly credentials: Credential.Store
  readonly orgs: Org.Store<OrgMeta>

  private _identities = new Map<string, Identities.Me<Profile>>()
  private _sessions = new Map<string, Sessions.Me>()
  private _credentials = new Map<string, Credential.Me>()
  private _orgs = new Map<string, Org.Me<OrgMeta>>()
  private _memberships = new Map<string, Org.Membership>()

  constructor() {
    // Brand here, not just in the factory below: `new MemoryAdapter()` is how every
    // example/test builds one, and strict() recognises a memory store by this flag.
    const brand = { __isMemoryStore: true as const }
    this.identities = Object.assign(this._buildIdentityStore(), brand)
    this.sessions = Object.assign(this._buildSessionStore(), brand)
    this.credentials = Object.assign(this._buildCredentialStore(), brand)
    this.orgs = Object.assign(this._buildOrgStore(), brand)
  }

  // --- Identity ---------------------------------------------------------

  private _buildIdentityStore(): Identities.Store<Profile> {
    const store = this._identities

    return {
      findById: async (id) => {
        const i = store.get(id)
        if (!i || isSoftDeleted(i)) return null
        return copy(i)
      },
      findByEmail: async (email) => {
        for (const i of store.values()) {
          if (isSoftDeleted(i)) continue
          if (sameEmail(getProfileString(i.profile, 'email'), email)) return copy(i)
        }
        return null
      },
      findByProviderSub: async (providerId, sub) => {
        for (const i of store.values()) {
          if (isSoftDeleted(i)) continue
          if (i.providers.some((p) => p.providerId === providerId && p.providerSub === sub)) {
            return copy(i)
          }
        }
        return null
      },
      create: async (input) => {
        // Atomic scan closes the race between two concurrent first-oauth-callbacks.
        const providers = input.providers ?? []
        for (const link of providers) {
          if (link.providerSub === null) continue
          for (const other of store.values()) {
            if (isSoftDeleted(other)) continue
            if (other.providers.some((p) => p.providerId === link.providerId && p.providerSub === link.providerSub)) {
              throw new AuthError('AUTH_PROVIDER_FAILED', {
                providerId: link.providerId,
                detail: 'provider sub already linked to a different identity',
              })
            }
          }
        }
        // Every dialect carries a partial unique index on `lower(email)` where
        // the row is live, so admitting a second one here would let a test pass
        // against state Postgres refuses to hold.
        const email = getProfileString(input.profile, 'email')
        for (const other of store.values()) {
          if (isSoftDeleted(other)) continue
          if (sameEmail(getProfileString(other.profile, 'email'), email)) {
            throw new AuthError('AUTH_EMAIL_TAKEN')
          }
        }
        const nowDate = new Date()
        const id: Identities.Me<Profile> = {
          ...input,
          id: randomToken(16),
          providers,
          // New identities are unverified unless the caller states otherwise.
          emailVerified: input.emailVerified ?? false,
          version: 1,
          createdAt: nowDate,
          updatedAt: nowDate,
          deletedAt: null,
        }
        return put(store, id.id, id)
      },
      update: async (id, patch, expectedVersion) => {
        const cur = store.get(id)
        // A conditional update matching nothing is a stale write whether the row
        // is gone or the version moved: the SQL bridges cannot tell the two
        // apart from `0 rows affected`, and a caller that retries needs one
        // answer, not one per adapter.
        if (!cur) throw new AuthError('AUTH_STALE_WRITE', { expected: expectedVersion, actual: -1 })
        if (cur.version !== expectedVersion) {
          throw new AuthError('AUTH_STALE_WRITE', {
            expected: expectedVersion,
            actual: cur.version,
          })
        }
        const next: Identities.Me<Profile> = {
          ...cur,
          ...stripUndefined(patch),
          version: cur.version + 1,
          updatedAt: new Date(),
        }
        return put(store, id, next)
      },
      softDelete: async (id, gracePeriodMs) => {
        const cur = store.get(id)
        // Already hidden: answering `null` matches what the set-based form
        // reports, and stops a second call pushing the grace window forward on a
        // row that was already eligible for purge.
        if (!cur || isSoftDeleted(cur)) return null
        // See the dialect bridges: the address is released while the row is
        // soft-deleted, so the verified claim must not survive the round trip.
        const next: Identities.Me<Profile> = {
          ...cur,
          deletedAt: new Date(Date.now() + gracePeriodMs),
          emailVerified: false,
        }
        return put(store, id, next)
      },
      restore: async (id) => {
        // No such row is `null`, matching `softDelete` and `erase`; the two
        // refusals below throw, because each names a rule the caller can act on.
        const cur = store.get(id)
        if (!cur) return null
        const deletedAtMs = cur.deletedAt?.getTime()
        if (!deletedAtMs || deletedAtMs < Date.now()) {
          throw new AuthError('AUTH_GRACE_EXPIRED')
        }
        // The address was free the whole time this row was hidden, so someone
        // may have taken it. There is no unique index here to catch it, which
        // would leave two live rows answering to the same email.
        const email = getProfileString(cur.profile, 'email')
        if (email !== undefined) {
          for (const other of store.values()) {
            if (other.id === id || isSoftDeleted(other)) continue
            if (sameEmail(getProfileString(other.profile, 'email'), email)) {
              throw new AuthError('AUTH_EMAIL_TAKEN')
            }
          }
        }
        // `Me.deletedAt` is non-optional (`Date | null`), so reset rather than omit.
        const next: Identities.Me<Profile> = { ...cur, deletedAt: null }
        return put(store, id, next)
      },
      erase: async (id) => {
        // Read before the delete, so the caller still gets the row it removed.
        const cur = store.get(id) ?? null
        store.delete(id)
        // Every dialect declares `identity_id ... on delete cascade` on the
        // credential, session and membership tables. Deleting only the identity
        // row here left a hard-deleted account with live credentials behind it -
        // and `credentials.findByHashedSecret` never joins back to identities,
        // so an API key for an erased account kept resolving.
        for (const [key, c] of this._credentials) {
          if (c.identityId === id) this._credentials.delete(key)
        }
        for (const [key, sess] of this._sessions) {
          if (sess.identityId === id) this._sessions.delete(key)
        }
        for (const [key, m] of this._memberships) {
          if (m.identityId === id) this._memberships.delete(key)
        }
        return cur ? copy(cur) : null
      },
      link: async (identityId, link) => {
        const cur = store.get(identityId)
        if (!cur) return null
        // Closes the TOCTOU window in `findByProviderSub` -> `link` under JS single-threading.
        if (link.providerSub !== null) {
          for (const [otherId, other] of store) {
            // A soft-deleted row holds nothing: it is already invisible to
            // `findByProviderSub`, so counting it here would let a hidden
            // account keep someone's provider login hostage forever while
            // nothing could ever read it back.
            if (otherId === identityId || isSoftDeleted(other)) continue
            if (other.providers.some((p) => p.providerId === link.providerId && p.providerSub === link.providerSub)) {
              throw new AuthError('AUTH_PROVIDER_FAILED', {
                providerId: link.providerId,
                detail: 'provider sub already linked to a different identity',
              })
            }
          }
        }
        // Re-linking the exact same `(providerId, providerSub)` is a no-op, not a
        // second entry: a retried OAuth callback is the ordinary way this is
        // reached, and appending would grow the JSON array without bound.
        if (cur.providers.some((p) => p.providerId === link.providerId && p.providerSub === link.providerSub)) {
          return copy(cur)
        }
        const next: Identities.Me<Profile> = { ...cur, providers: [...cur.providers, link] }
        return put(store, identityId, next)
      },
      unlink: async (identityId, providerId) => {
        const cur = store.get(identityId)
        if (!cur) return null
        const next: Identities.Me<Profile> = {
          ...cur,
          providers: cur.providers.filter((p) => p.providerId !== providerId),
        }
        return put(store, identityId, next)
      },
      merge: async (survivorId, dupId) => {
        const survivor = store.get(survivorId)
        if (!survivor) return null
        // Merging a row into itself would otherwise delete it: the reassignment
        // loops run, then `store.delete(dupId)` removes the survivor and the
        // caller is handed a row that is no longer in the store.
        if (survivorId === dupId) return copy(survivor)
        const dup = store.get(dupId)
        if (!dup) return null
        // A duplicate account usually exists *because* it signed in through the
        // same provider, so concatenating unfiltered produced two links sharing a
        // `providerId` - which `unlink` then removes both of, and which no unique
        // index would have permitted in the first place.
        const providers = [...survivor.providers]
        for (const link of dup.providers) {
          if (providers.some((p) => p.providerId === link.providerId && p.providerSub === link.providerSub)) continue
          providers.push(link)
        }
        const merged: Identities.Me<Profile> = { ...survivor, providers }
        put(store, survivorId, merged)
        for (const c of this._credentials.values()) {
          if (c.identityId === dupId) {
            this._credentials.set(c.id, copy({ ...c, identityId: survivorId }))
          }
        }
        // Sessions were the omission that mattered: the dup's live sessions kept
        // pointing at an id that no longer resolves, so `listByIdentity` on the
        // survivor could not see them and `revokeAll` could not end them - the
        // merged-away account stayed signed in with no way to sign it out.
        for (const [key, sess] of this._sessions) {
          if (sess.identityId === dupId) {
            this._sessions.set(key, copy({ ...sess, identityId: survivorId }))
          }
        }
        for (const [key, m] of this._memberships) {
          if (m.identityId !== dupId) continue
          this._memberships.delete(key)
          const survivorKey = `${m.orgId}:${survivorId}`
          const existing = this._memberships.get(survivorKey)
          // Both accounts in the same org: keep the survivor's own membership and
          // union the roles onto it. Overwriting was a silent privilege change in
          // whichever direction the iteration happened to run.
          this._memberships.set(
            survivorKey,
            copy(
              existing
                ? { ...existing, roles: [...new Set([...existing.roles, ...m.roles])] }
                : { ...m, identityId: survivorId },
            ),
          )
        }
        store.delete(dupId)
        // The survivor, which is the row the caller still has a use for.
        return copy(merged)
      },
    }
  }

  // --- Session ----------------------------------------------------------

  private _buildSessionStore(): Sessions.Store {
    const store = this._sessions
    return {
      create: async (s) => {
        // Fill nullable columns the caller omitted, so the store holds a complete row.
        const row: Sessions.Me = {
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
        }
        put(store, row.id, row)
      },
      getByHash: async (sidHash) => {
        const row = store.get(sidHash)
        return row ? copy(row) : null
      },
      update: async (id, patch) => {
        const cur = store.get(id)
        // Redis and SQL both surface a missing row as AUTH_SESSION_REVOKED; keep memory in step.
        if (!cur) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })
        // No implicit `rotatedAt` stamp: moving it on every patch would mask an expired gate.
        // `id` is pinned to the row that was addressed: the key is the sid hash the
        // caller's cookie carries, so a patch that moved it would leave the row
        // filed under a hash that no longer matches its own `id` - `getByHash`
        // would keep answering, while `revoke(next.id)` deleted nothing.
        const next: Sessions.Me = { ...cur, ...stripUndefined(patch), id: cur.id }
        return put(store, id, next)
      },
      delete: async (id) => {
        store.delete(id)
      },
      listByIdentity: async (identityId) => {
        return [...store.values()].filter((s) => s.identityId === identityId).map(copy)
      },
      deleteAllForIdentity: async (identityId) => {
        for (const s of store.values()) if (s.identityId === identityId) store.delete(s.id)
      },
      gc: async (now) => {
        let deleted = 0
        for (const s of store.values()) {
          const expiresAtMs = s.expiresAt.getTime()
          const absExpiresAtMs = s.absoluteExpiresAt.getTime()
          if (expiresAtMs < now || absExpiresAtMs < now) {
            store.delete(s.id)
            deleted++
          }
        }
        return { deleted }
      },
    }
  }

  // --- Credential -------------------------------------------------------

  private _buildCredentialStore(): Credential.Store & {
    __familyRevoke: (familyId: string, ctx: TenantContext) => Promise<void>
  } {
    const store = this._credentials
    /**
     * The one tenant predicate every read and write shares. An undefined
     * `ctx.tenantId` is an unscoped caller and sees everything; a set one sees
     * only its own rows.
     *
     * Memory used to also admit global (`tenantId === null`) rows to a scoped
     * caller, and a test asserted that as "SQL adapter parity". It is not: every
     * dialect scopes with a bare `eq(tenant_id, $1)`, and SQL NULL is equal to
     * nothing, so a global credential is invisible to every tenant on every real
     * backend. The permissive version made a row with no tenant usable by all of
     * them - so the reference adapter follows the dialects rather than the other
     * way round, which is also the only direction that narrows.
     *
     * Only `findByHashedSecret` and `upsert` used to consult `ctx` at all. The
     * other nine took it and ignored it, so on memory a tenant could read,
     * rotate, revoke and delete another tenant's credentials by id - the exact
     * isolation the parameter exists to enforce, absent from the adapter the
     * compliance suite treats as the reference.
     */
    const visible = (c: Credential.Me, ctx: TenantContext | undefined): boolean =>
      ctx?.tenantId === undefined || c.tenantId === ctx.tenantId
    return {
      findById: async (id, ctx) => {
        const c = store.get(id)
        return c && visible(c, ctx) ? copy(c) : null
      },
      listByIdentity: async (identityId, kind, ctx) => {
        return [...store.values()]
          .filter((c) => c.identityId === identityId && (kind == null || c.kind === kind) && visible(c, ctx))
          .map(copy)
      },
      findByProviderSub: async (provider, sub, ctx) => {
        for (const c of store.values()) {
          if (c.kind !== 'oauth') continue
          if (!visible(c, ctx)) continue
          if (c.metadata?.provider === provider && c.metadata?.sub === sub) return copy(c)
        }
        return null
      },
      findByHashedSecret: async (secretHash, kind, ctx) => {
        // Prefer freshest live, fall back to revoked. timingSafeEqual defeats hash oracles.
        // Tenant filter: undefined ctx.tenantId matches globally; set matches exactly.
        let live: Credential.Me | null = null
        let revokedRow: Credential.Me | null = null
        for (const c of store.values()) {
          if (c.kind !== kind) continue
          if (!timingSafeEqual(c.secret, secretHash)) continue
          if (!visible(c, ctx)) continue
          const cCreatedMs = c.createdAt.getTime()
          if (isRevoked(c)) {
            if (!revokedRow || cCreatedMs > revokedRow.createdAt.getTime()) revokedRow = c
          } else {
            if (!live || cCreatedMs > live.createdAt.getTime()) live = c
          }
        }
        const found = live ?? revokedRow
        return found ? copy(found) : null
      },
      upsert: async (input, ctx) => {
        const id = randomToken(16)
        // Inherit tenantId from ctx when input doesn't set it.
        const c: Credential.Me = {
          id,
          identityId: input.identityId,
          tenantId: input.tenantId ?? ctx?.tenantId ?? null,
          kind: input.kind,
          secret: input.secret,
          metadata: input.metadata ?? null,
          version: 1,
          createdAt: new Date(),
          lastUsedAt: input.lastUsedAt ?? null,
          expiresAt: input.expiresAt ?? null,
          revokedAt: input.revokedAt ?? null,
        }
        return put(store, id, c)
      },
      rotate: async (id, newSecret, expectedVersion, ctx) => {
        const cur = store.get(id)
        // Out of tenant is indistinguishable from gone, and both are stale
        // writes: the conditional UPDATE the dialects issue matches no row
        // either way and reports `0 rows affected`.
        if (!cur || !visible(cur, ctx)) {
          throw new AuthError('AUTH_STALE_WRITE', { expected: expectedVersion, actual: -1 })
        }
        if (cur.version !== expectedVersion) {
          throw new AuthError('AUTH_STALE_WRITE', {
            expected: expectedVersion,
            actual: cur.version,
          })
        }
        const next: Credential.Me = {
          ...cur,
          // A rotation is a use. `sql.ts` stamps it on the same write; without it
          // memory reported a credential as never used after its secret changed,
          // which is what an idle-credential reaper reads to decide what to cull.
          lastUsedAt: new Date(),
          secret: newSecret,
          version: cur.version + 1,
        }
        return put(store, id, next)
      },
      patchMetadata: async (id, patch, ctx) => {
        const cur = store.get(id)
        if (!cur || !visible(cur, ctx)) {
          throw new AuthError('AUTH_STALE_WRITE', { expected: -1, actual: -1 })
        }
        const next: Credential.Me = {
          ...cur,
          metadata: { ...(cur.metadata ?? {}), ...patch },
          version: cur.version + 1,
        }
        return put(store, id, next)
      },
      revoke: async (id, ctx) => {
        const cur = store.get(id)
        if (!cur || !visible(cur, ctx)) return null
        const next = { ...cur, revokedAt: cur.revokedAt ?? new Date() }
        return put(store, id, next)
      },
      delete: async (id, ctx) => {
        // Read before the delete: this is the caller's last look at the row.
        const cur = store.get(id) ?? null
        if (!cur || !visible(cur, ctx)) return null
        store.delete(id)
        return copy(cur)
      },
      deleteByKind: async (identityId, kind, ctx) => {
        const removed: Credential.Me[] = []
        for (const c of store.values()) {
          if (c.identityId === identityId && c.kind === kind && visible(c, ctx)) {
            removed.push(copy(c))
            store.delete(c.id)
          }
        }
        return removed
      },
      // oauth refresh-reuse hook; memory walks every row (prod indexes by familyId).
      __familyRevoke: async (familyId: string, ctx: TenantContext) => {
        const nowDate = new Date()
        for (const c of store.values()) {
          if (c.kind !== 'oauth') continue
          if (!visible(c, ctx)) continue
          if (c.metadata?.familyId !== familyId) continue
          store.set(c.id, copy({ ...c, revokedAt: c.revokedAt ?? nowDate }))
        }
      },
    }
  }

  // --- Org --------------------------------------------------------------

  private _buildOrgStore(): Org.Store<OrgMeta> {
    return {
      getOrg: async (id) => {
        const org = this._orgs.get(id)
        return org ? copy(org) : null
      },
      listOrgsForIdentity: async (identityId) => {
        const orgIds = new Set<string>()
        for (const m of this._memberships.values()) {
          if (m.identityId === identityId && !m.leftAt) orgIds.add(m.orgId)
        }
        return [...orgIds]
          .map((id) => this._orgs.get(id))
          .filter((o): o is Org.Me<OrgMeta> => Boolean(o))
          .map(copy)
      },
      listMembers: async (orgId) => {
        return [...this._memberships.values()].filter((m) => m.orgId === orgId && !m.leftAt).map(copy)
      },
      addMember: async (m) => {
        // CAS under JS single-threading; SQL uses partial UNIQUE on (orgId, identityId).
        const key = `${m.orgId}:${m.identityId}`
        const cur = this._memberships.get(key)
        if (cur && cur.leftAt === null) {
          throw new AuthError('AUTH_PROVIDER_FAILED', {
            providerId: 'orgs',
            detail: 'identity already a member of this org',
          })
        }
        // `Org.Store` has no `createOrg` - orgs are created by the host app, in
        // its own tables, and this store only ever reads them. That left `_orgs`
        // with no writer at all, so `getOrg` answered `null` and
        // `listOrgsForIdentity` answered `[]` for memberships this same adapter
        // was holding: a test could add a member and then be told the org does
        // not exist. Registering a stub on first membership keeps the two reads
        // consistent with the writes; `name` is the id because a dev adapter has
        // nothing truer to use, and a caller that wants real fields sets them
        // with `seedOrg`.
        if (!this._orgs.has(m.orgId)) {
          const stub: Org.Me<OrgMeta> = {
            createdAt: new Date(),
            domain: null,
            id: m.orgId,
            metadata: null,
            name: m.orgId,
          }
          this._orgs.set(m.orgId, stub)
        }
        const full: Org.Membership = { ...m, invitedAt: m.invitedAt ?? null, joinedAt: new Date(), leftAt: null }
        return put(this._memberships, key, full)
      },
      removeMember: async (orgId, identityId) => {
        const key = `${orgId}:${identityId}`
        const cur = this._memberships.get(key)
        if (!cur) return null
        const next = { ...cur, leftAt: cur.leftAt ?? new Date() }
        return put(this._memberships, key, next)
      },
      setRoles: async (orgId, identityId, roles) => {
        const key = `${orgId}:${identityId}`
        const cur = this._memberships.get(key)
        if (!cur) return null
        const next = { ...cur, roles: [...roles] }
        return put(this._memberships, key, next)
      },
    }
  }

  /**
   * Register an org row so `getOrg` and `listOrgsForIdentity` return something
   * meaningful. Orgs live in the host app's own tables - `Org.Store` is a read
   * interface over them - so there is no `createOrg` to call, and a test that
   * wants real names, domains or metadata has to put them here.
   */
  seedOrg(org: Org.Me<OrgMeta>): Org.Me<OrgMeta> {
    return put(this._orgs, org.id, org)
  }

  /**
   * The stored rows themselves, for tests only.
   *
   * Every store method copies on the way in and on the way out, which is what
   * makes this adapter behave like a database - and which also removes the only
   * way a test had to plant a row no store API would ever produce: a `revokedAt`
   * holding a string, an `expiresAt` that is not a date, a factor with a method
   * outside the union. Those rows are the point of the fail-closed tests: they
   * stand in for a third-party adapter that hands the library something its
   * types promised it would not.
   *
   * So the escape hatch is named rather than incidental. Writes here bypass the
   * copy boundary deliberately; nothing in the library reads it.
   */
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

/**
 * Storage helper returning the in-memory `{ identities, sessions, credentials }` triple. Dev / test only.
 *
 * @template Profile - Identity profile shape.
 */
export const memoryStorage = <Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(): {
  identities: MemoryAdapter<Profile>['identities']
  sessions: MemoryAdapter<Profile>['sessions']
  credentials: MemoryAdapter<Profile>['credentials']
} => {
  const adapter = new MemoryAdapter<Profile>()
  // Branded so strict() can recognise these without reading `constructor.name`, which
  // every sql/drizzle/prisma store shares as a plain object literal.
  const brand = { __isMemoryStore: true as const }
  return {
    credentials: Object.assign(adapter.credentials, brand),
    identities: Object.assign(adapter.identities, brand),
    sessions: Object.assign(adapter.sessions, brand),
  }
}

/** Factory around {@link MemoryAdapter}, for callers who prefer functions to `new`. */
export function memoryAdapter(...args: ConstructorParameters<typeof MemoryAdapter>): MemoryAdapter {
  return new MemoryAdapter(...args)
}
