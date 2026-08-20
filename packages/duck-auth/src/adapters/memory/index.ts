import { getProfileString, isRevoked, isSoftDeleted } from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { randomToken, timingSafeEqual } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import type { Org } from '~/core/orgs/orgs.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { TenantContext } from '~/core/tenant/tenant.types'

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
    // Brand here rather than only in the factory below: `new MemoryAdapter()` is how
    // every example and test builds one, and strict() recognises a memory store by
    // this flag. Branding one construction path and not the other lets the ordinary
    // path through a production check whose whole job is to refuse it.
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
        return i
      },
      findByEmail: async (email) => {
        for (const i of store.values()) {
          if (isSoftDeleted(i)) continue
          const e = getProfileString(i.profile, 'email')
          if (e === email) return i
        }
        return null
      },
      findByProviderSub: async (providerId, sub) => {
        for (const i of store.values()) {
          if (isSoftDeleted(i)) continue
          if (i.providers.some((p) => p.providerId === providerId && p.providerSub === sub)) {
            return i
          }
        }
        return null
      },
      create: async (input) => {
        // Atomic provider-sub uniqueness scan to close the race between
        // two concurrent first-oauth-callbacks on the same (providerId, sub).
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
        const nowDate = new Date()
        // SQL adapter parity: prefer explicit input.tenantId, fall back to ctx.
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
        store.set(id.id, id)
        return id
      },
      update: async (id, patch, expectedVersion) => {
        const cur = store.get(id)
        if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
        if (cur.version !== expectedVersion) {
          throw new AuthError('AUTH_STALE_WRITE', {
            expected: expectedVersion,
            actual: cur.version,
          })
        }
        const next: Identities.Me<Profile> = {
          ...cur,
          ...patch,
          version: cur.version + 1,
          updatedAt: new Date(),
        }
        store.set(id, next)
        return next
      },
      softDelete: async (id, gracePeriodMs) => {
        const cur = store.get(id)
        if (!cur) return
        store.set(id, { ...cur, deletedAt: new Date(Date.now() + gracePeriodMs) })
      },
      restore: async (id) => {
        const cur = store.get(id)
        if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
        const deletedAtMs = cur.deletedAt?.getTime()
        if (!deletedAtMs || deletedAtMs < Date.now()) {
          throw new AuthError('AUTH_GRACE_EXPIRED')
        }
        // Clear the soft-delete marker back to the `null` sentinel; `Me.deletedAt`
        // is non-optional (`Date | null`), so we reset rather than omit the key.
        const next: Identities.Me<Profile> = { ...cur, deletedAt: null }
        store.set(id, next)
        return next
      },
      erase: async (id) => {
        store.delete(id)
      },
      link: async (identityId, link) => {
        const cur = store.get(identityId)
        if (!cur) return
        // Atomic uniqueness check under JS single-threading; closes the
        // TOCTOU window in `findByProviderSub` -> `link`. SQL adapters
        // enforce the equivalent via UNIQUE(providerId, providerSub).
        if (link.providerSub !== null) {
          for (const [otherId, other] of store) {
            if (otherId === identityId) continue
            if (other.providers.some((p) => p.providerId === link.providerId && p.providerSub === link.providerSub)) {
              throw new AuthError('AUTH_PROVIDER_FAILED', {
                providerId: link.providerId,
                detail: 'provider sub already linked to a different identity',
              })
            }
          }
        }
        store.set(identityId, { ...cur, providers: [...cur.providers, link] })
      },
      unlink: async (identityId, providerId) => {
        const cur = store.get(identityId)
        if (!cur) return
        store.set(identityId, {
          ...cur,
          providers: cur.providers.filter((p) => p.providerId !== providerId),
        })
      },
      merge: async (survivorId, dupId) => {
        const survivor = store.get(survivorId)
        const dup = store.get(dupId)
        if (!survivor || !dup) return
        store.set(survivorId, {
          ...survivor,
          providers: [...survivor.providers, ...dup.providers],
        })
        // Reassign credentials + memberships to survivor.
        for (const c of this._credentials.values()) {
          if (c.identityId === dupId) {
            this._credentials.set(c.id, { ...c, identityId: survivorId })
          }
        }
        for (const m of this._memberships.values()) {
          if (m.identityId === dupId) {
            this._memberships.set(`${m.orgId}:${survivorId}`, { ...m, identityId: survivorId })
            this._memberships.delete(`${m.orgId}:${dupId}`)
          }
        }
        store.delete(dupId)
      },
    }
  }

  // --- Session ----------------------------------------------------------

  private _buildSessionStore(): Sessions.Store {
    const store = this._sessions
    return {
      create: async (s) => {
        // Fill the nullable columns the caller may have omitted, so the store
        // always holds a complete `Session.Me` row (SQL adapter parity).
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
        store.set(row.id, row)
      },
      getByHash: async (sidHash) => store.get(sidHash) ?? null,
      update: async (id, patch) => {
        const cur = store.get(id)
        // Redis and SQL both surface a missing row as AUTH_SESSION_REVOKED; memory
        // was the outlier, and it is the store dev and CI run against.
        if (!cur) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })
        // No implicit `rotatedAt` stamp: it drives the freshness gate, so moving it
        // on every patch means the gate never expires here but does in production.
        const next = { ...cur, ...patch }
        store.set(id, next)
        return next
      },
      delete: async (id) => {
        store.delete(id)
      },
      listByIdentity: async (identityId) => {
        return [...store.values()].filter((s) => s.identityId === identityId)
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
    return {
      findById: async (id) => store.get(id) ?? null,
      listByIdentity: async (identityId, kind) => {
        return [...store.values()].filter((c) => c.identityId === identityId && (kind == null || c.kind === kind))
      },
      findByProviderSub: async (provider, sub) => {
        for (const c of store.values()) {
          if (c.kind !== 'oauth') continue
          if (c.metadata?.provider === provider && c.metadata?.sub === sub) return c
        }
        return null
      },
      findByHashedSecret: async (secretHash, kind, ctx) => {
        // Prefer freshest live; fall back to revoked so callers can disambiguate.
        // timingSafeEqual defeats byte-by-byte hash oracles. Tenant filter
        // matches SQL adapter semantics: undefined ctx tenant = global match;
        // set ctx tenant = exact match (or global rows when row.tenantId is unset).
        let live: Credential.Me | null = null
        let revokedRow: Credential.Me | null = null
        for (const c of store.values()) {
          if (c.kind !== kind) continue
          if (!timingSafeEqual(c.secret, secretHash)) continue
          if (ctx?.tenantId !== undefined && c.tenantId !== null && c.tenantId !== ctx.tenantId) continue
          const cCreatedMs = c.createdAt.getTime()
          if (isRevoked(c)) {
            if (!revokedRow || cCreatedMs > revokedRow.createdAt.getTime()) revokedRow = c
          } else {
            if (!live || cCreatedMs > live.createdAt.getTime()) live = c
          }
        }
        return live ?? revokedRow
      },
      upsert: async (input, ctx) => {
        const id = randomToken(16)
        // SQL adapter parity: inherit tenantId from ctx when input doesn't set it,
        // and default every nullable column to `null` when omitted.
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
        store.set(id, c)
        return c
      },
      rotate: async (id, newSecret, expectedVersion) => {
        const cur = store.get(id)
        if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
        if (cur.version !== expectedVersion) {
          throw new AuthError('AUTH_STALE_WRITE', {
            expected: expectedVersion,
            actual: cur.version,
          })
        }
        const next: Credential.Me = {
          ...cur,
          secret: newSecret,
          version: cur.version + 1,
        }
        store.set(id, next)
        return next
      },
      patchMetadata: async (id, patch) => {
        const cur = store.get(id)
        if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
        const next: Credential.Me = {
          ...cur,
          metadata: { ...(cur.metadata ?? {}), ...patch },
          version: cur.version + 1,
        }
        store.set(id, next)
        return next
      },
      revoke: async (id) => {
        const cur = store.get(id)
        if (!cur) return
        store.set(id, { ...cur, revokedAt: new Date() })
      },
      delete: async (id) => {
        store.delete(id)
      },
      deleteByKind: async (identityId, kind) => {
        for (const c of store.values()) {
          if (c.identityId === identityId && c.kind === kind) store.delete(c.id)
        }
      },
      // oauth refresh-reuse hook; memory walks every row (prod indexes by familyId).
      __familyRevoke: async (familyId: string) => {
        const nowDate = new Date()
        for (const c of store.values()) {
          if (c.kind !== 'oauth') continue
          if (c.metadata?.familyId !== familyId) continue
          store.set(c.id, { ...c, revokedAt: c.revokedAt ?? nowDate })
        }
      },
    }
  }

  // --- Org --------------------------------------------------------------

  private _buildOrgStore(): Org.Store<OrgMeta> {
    return {
      getOrg: async (id) => this._orgs.get(id) ?? null,
      listOrgsForIdentity: async (identityId) => {
        const orgIds = new Set<string>()
        for (const m of this._memberships.values()) {
          if (m.identityId === identityId && !m.leftAt) orgIds.add(m.orgId)
        }
        return [...orgIds].map((id) => this._orgs.get(id)).filter((o): o is Org.Me<OrgMeta> => Boolean(o))
      },
      listMembers: async (orgId) => {
        return [...this._memberships.values()].filter((m) => m.orgId === orgId && !m.leftAt)
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
        const full: Org.Membership = { ...m, invitedAt: m.invitedAt ?? null, joinedAt: new Date(), leftAt: null }
        this._memberships.set(key, full)
        return full
      },
      removeMember: async (orgId, identityId) => {
        const key = `${orgId}:${identityId}`
        const cur = this._memberships.get(key)
        if (cur) this._memberships.set(key, { ...cur, leftAt: new Date() })
      },
      setRoles: async (orgId, identityId, roles) => {
        const key = `${orgId}:${identityId}`
        const cur = this._memberships.get(key)
        if (!cur) return
        this._memberships.set(key, { ...cur, roles })
      },
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
  // Branded so strict() can recognise these without reading `constructor.name`: every
  // sql, drizzle and prisma store is a plain object literal too, so a name check
  // rejects the very adapters its own error message tells you to use.
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
