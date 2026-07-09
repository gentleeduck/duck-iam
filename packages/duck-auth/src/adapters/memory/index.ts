import { getProfileString, isRevoked, isSoftDeleted } from '~/core/credential-utils'
import { randomToken, timingSafeEqual } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { Session } from '~/core/sessions/sessions.types'
import type { Credential, Identity, Org } from '~/core/types/identity'
import type { TenantContext } from '~/core/types/infra'

/**
 * In-memory adapter - dev + test only. Production must use redis/drizzle/prisma.
 * Strict mode rejects this adapter when `env: 'production'`.
 *
 * Multi-tenant: tenantId filters every query so tests can verify isolation.
 */
export class MemoryAdapter<
  Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  OrgMeta = unknown,
> {
  readonly identities: Identity.Store<Profile>
  readonly sessions: Session.Store
  readonly credentials: Credential.Store
  readonly orgs: Org.Store<OrgMeta>

  private _identities = new Map<string, Identity.Me<Profile>>()
  private _sessions = new Map<string, Session.Me>()
  private _credentials = new Map<string, Credential.Me>()
  private _orgs = new Map<string, Org.Me<OrgMeta>>()
  private _memberships = new Map<string, Org.Membership>()

  constructor() {
    this.identities = this._buildIdentityStore()
    this.sessions = this._buildSessionStore()
    this.credentials = this._buildCredentialStore()
    this.orgs = this._buildOrgStore()
  }

  // --- Identity ---------------------------------------------------------

  private _buildIdentityStore(): Identity.Store<Profile> {
    const store = this._identities
    const filter = (id: Identity.Me<Profile>, ctx: TenantContext) =>
      ctx.tenantId === undefined || id.tenantId === ctx.tenantId

    return {
      findById: async (id, ctx) => {
        const i = store.get(id)
        return i && filter(i, ctx) && !isSoftDeleted(i) ? i : null
      },
      findByEmail: async (email, ctx) => {
        for (const i of store.values()) {
          if (!filter(i, ctx) || isSoftDeleted(i)) continue
          const e = getProfileString(i.profile, 'email')
          if (e === email) return i
        }
        return null
      },
      findByProviderSub: async (providerId, sub, ctx) => {
        for (const i of store.values()) {
          if (!filter(i, ctx) || isSoftDeleted(i)) continue
          if (i.providers.some((p) => p.providerId === providerId && p.providerSub === sub)) {
            return i
          }
        }
        return null
      },
      create: async (input, ctx) => {
        // Atomic provider-sub uniqueness scan to close the race between
        // two concurrent first-oauth-callbacks on the same (providerId, sub).
        const providers = input.providers ?? []
        for (const link of providers) {
          if (link.providerSub === null) continue
          for (const other of store.values()) {
            if (filter(other, ctx) === false || isSoftDeleted(other)) continue
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
        const id: Identity.Me<Profile> = {
          ...input,
          id: randomToken(16),
          tenantId: input.tenantId ?? ctx.tenantId ?? null,
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
      update: async (id, patch, expectedVersion, _ctx) => {
        const cur = store.get(id)
        if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
        if (cur.version !== expectedVersion) {
          throw new AuthError('AUTH_STALE_WRITE', {
            expected: expectedVersion,
            actual: cur.version,
          })
        }
        const next: Identity.Me<Profile> = {
          ...cur,
          ...patch,
          version: cur.version + 1,
          updatedAt: new Date(),
        }
        store.set(id, next)
        return next
      },
      softDelete: async (id, gracePeriodMs, _ctx) => {
        const cur = store.get(id)
        if (!cur) return
        store.set(id, { ...cur, deletedAt: new Date(Date.now() + gracePeriodMs) })
      },
      restore: async (id, _ctx) => {
        const cur = store.get(id)
        if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
        const deletedAtMs = cur.deletedAt?.getTime()
        if (!deletedAtMs || deletedAtMs < Date.now()) {
          throw new AuthError('AUTH_GRACE_EXPIRED')
        }
        // Clear the soft-delete marker back to the `null` sentinel; `Me.deletedAt`
        // is non-optional (`Date | null`), so we reset rather than omit the key.
        const next: Identity.Me<Profile> = { ...cur, deletedAt: null }
        store.set(id, next)
        return next
      },
      erase: async (id, _ctx) => {
        store.delete(id)
      },
      link: async (identityId, link, _ctx) => {
        const cur = store.get(identityId)
        if (!cur) return
        // Atomic uniqueness check under JS single-threading; closes the
        // TOCTOU window in `findByProviderSub` -> `link`. SQL adapters
        // enforce the equivalent via UNIQUE(providerId, providerSub).
        if (link.providerSub !== null) {
          for (const [otherId, other] of store) {
            if (otherId === identityId) continue
            if (filter(other, _ctx) === false || isSoftDeleted(other)) continue
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
      unlink: async (identityId, providerId, _ctx) => {
        const cur = store.get(identityId)
        if (!cur) return
        store.set(identityId, {
          ...cur,
          providers: cur.providers.filter((p) => p.providerId !== providerId),
        })
      },
      merge: async (survivorId, dupId, _ctx) => {
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

  private _buildSessionStore(): Session.Store {
    const store = this._sessions
    return {
      create: async (s) => {
        // Fill the nullable columns the caller may have omitted, so the store
        // always holds a complete `Session.Me` row (SQL adapter parity).
        const row: Session.Me = {
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
        if (!cur) throw new AuthError('AUTH_UNAUTHENTICATED')
        const next = { ...cur, ...patch, rotatedAt: new Date() }
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
export const memoryStorage = <Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(): {
  identities: MemoryAdapter<Profile>['identities']
  sessions: MemoryAdapter<Profile>['sessions']
  credentials: MemoryAdapter<Profile>['credentials']
} => {
  const adapter = new MemoryAdapter<Profile>()
  return {
    credentials: adapter.credentials,
    identities: adapter.identities,
    sessions: adapter.sessions,
  }
}
