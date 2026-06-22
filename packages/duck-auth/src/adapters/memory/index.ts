import { getProfileString, isRevoked, isSoftDeleted } from '../../core/credential-utils'
import { authRandomToken, authTimingSafeEqual } from '../../core/crypto'
import { AuthErrorObject } from '../../core/errors'
import type { AuthTenantContext } from '../../core/types/context'
import type { AuthCredential } from '../../core/types/credential'
import type { AuthIdentity } from '../../core/types/identity'
import type { AuthOrg } from '../../core/types/org'
import type { AuthSession } from '../../core/types/session'

/**
 * In-memory adapter - dev + test only. Production must use redis/drizzle/prisma.
 * Strict mode rejects this adapter when `env: 'production'`.
 *
 * Multi-tenant: tenantId filters every query so tests can verify isolation.
 */
export class MemoryAdapter<Profile = unknown, OrgMeta = unknown> {
  readonly identities: AuthIdentity.IStore<Profile>
  readonly sessions: AuthSession.IStore
  readonly credentials: AuthCredential.IStore
  readonly orgs: AuthOrg.IStore<OrgMeta>

  private _identities = new Map<string, AuthIdentity.IIdentity<Profile>>()
  private _sessions = new Map<string, AuthSession.ISession>()
  private _credentials = new Map<string, AuthCredential.ICredential>()
  private _orgs = new Map<string, AuthOrg.IOrg<OrgMeta>>()
  private _memberships = new Map<string, AuthOrg.IMembership>()

  constructor() {
    this.identities = this._buildIdentityStore()
    this.sessions = this._buildSessionStore()
    this.credentials = this._buildCredentialStore()
    this.orgs = this._buildOrgStore()
  }

  // --- AuthIdentity ---------------------------------------------------------

  private _buildIdentityStore(): AuthIdentity.IStore<Profile> {
    const store = this._identities
    const filter = (id: AuthIdentity.IIdentity<Profile>, ctx: AuthTenantContext) =>
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
        // two concurrent first-OAuth-callbacks on the same (providerId, sub).
        const providers = input.providers ?? []
        for (const link of providers) {
          if (link.providerSub === undefined) continue
          for (const other of store.values()) {
            if (filter(other, ctx) === false || isSoftDeleted(other)) continue
            if (other.providers.some((p) => p.providerId === link.providerId && p.providerSub === link.providerSub)) {
              throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
                providerId: link.providerId,
                detail: 'provider sub already linked to a different identity',
              })
            }
          }
        }
        const now = Date.now()
        // SQL adapter parity: prefer explicit input.tenantId, fall back to ctx.
        const id: AuthIdentity.IIdentity<Profile> = {
          ...input,
          id: authRandomToken(16),
          tenantId: input.tenantId ?? ctx.tenantId,
          providers,
          version: 1,
          createdAt: now,
          updatedAt: now,
        }
        store.set(id.id, id)
        return id
      },
      update: async (id, patch, expectedVersion, _ctx) => {
        const cur = store.get(id)
        if (!cur) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
        if (cur.version !== expectedVersion) {
          throw new AuthErrorObject('AUTH/STALE_WRITE', {
            expected: expectedVersion,
            actual: cur.version,
          })
        }
        const next: AuthIdentity.IIdentity<Profile> = {
          ...cur,
          ...patch,
          version: cur.version + 1,
          updatedAt: Date.now(),
        }
        store.set(id, next)
        return next
      },
      softDelete: async (id, gracePeriodMs, _ctx) => {
        const cur = store.get(id)
        if (!cur) return
        store.set(id, { ...cur, deletedAt: Date.now() + gracePeriodMs })
      },
      restore: async (id, _ctx) => {
        const cur = store.get(id)
        if (!cur) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
        if (!cur.deletedAt || cur.deletedAt < Date.now()) {
          throw new AuthErrorObject('AUTH/GRACE_EXPIRED')
        }
        // Destructure-and-omit drops the `deletedAt` key entirely
        // (better than `deletedAt: undefined`, which is rejected by
        // `exactOptionalPropertyTypes` and forced the legacy cast).
        const { deletedAt: _deletedAt, ...next } = cur
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
        if (link.providerSub !== undefined) {
          for (const [otherId, other] of store) {
            if (otherId === identityId) continue
            if (filter(other, _ctx) === false || isSoftDeleted(other)) continue
            if (other.providers.some((p) => p.providerId === link.providerId && p.providerSub === link.providerSub)) {
              throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
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

  // --- AuthSession ----------------------------------------------------------

  private _buildSessionStore(): AuthSession.IStore {
    const store = this._sessions
    return {
      create: async (s) => {
        store.set(s.id, s)
      },
      getByHash: async (sidHash) => store.get(sidHash) ?? null,
      update: async (id, patch) => {
        const cur = store.get(id)
        if (!cur) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
        const next = { ...cur, ...patch, rotatedAt: Date.now() }
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
          if (s.expiresAt < now || s.absoluteExpiresAt < now) {
            store.delete(s.id)
            deleted++
          }
        }
        return { deleted }
      },
    }
  }

  // --- AuthCredential -------------------------------------------------------

  private _buildCredentialStore(): AuthCredential.IStore & {
    __familyRevoke: (familyId: string, ctx: AuthTenantContext) => Promise<void>
  } {
    const store = this._credentials
    return {
      findById: async (id) => store.get(id) ?? null,
      listByIdentity: async (identityId, kind) => {
        return [...store.values()].filter((c) => c.identityId === identityId && (kind === undefined || c.kind === kind))
      },
      findByProviderSub: async (provider, sub) => {
        for (const c of store.values()) {
          if (c.kind !== 'oauth') continue
          const m = c.metadata as { provider?: string; sub?: string } | undefined
          if (m?.provider === provider && m.sub === sub) return c
        }
        return null
      },
      findByHashedSecret: async (secretHash, kind, ctx) => {
        // Prefer freshest live; fall back to revoked so callers can disambiguate.
        // timingSafeEqual defeats byte-by-byte hash oracles. Tenant filter
        // matches SQL adapter semantics: undefined ctx tenant = global match;
        // set ctx tenant = exact match (or global rows when row.tenantId is unset).
        let live: AuthCredential.ICredential | null = null
        let revokedRow: AuthCredential.ICredential | null = null
        for (const c of store.values()) {
          if (c.kind !== kind) continue
          if (!authTimingSafeEqual(c.secret, secretHash)) continue
          if (ctx?.tenantId !== undefined && c.tenantId !== undefined && c.tenantId !== ctx.tenantId) continue
          if (isRevoked(c)) {
            if (!revokedRow || c.createdAt > revokedRow.createdAt) revokedRow = c
          } else {
            if (!live || c.createdAt > live.createdAt) live = c
          }
        }
        return live ?? revokedRow
      },
      upsert: async (input, ctx) => {
        const id = authRandomToken(16)
        const now = Date.now()
        // SQL adapter parity: inherit tenantId from ctx when input doesn't set it.
        const c: AuthCredential.ICredential = {
          id,
          version: 1,
          createdAt: now,
          ...input,
          ...(input.tenantId === undefined && ctx?.tenantId !== undefined && { tenantId: ctx.tenantId }),
        }
        store.set(id, c)
        return c
      },
      rotate: async (id, newSecret, expectedVersion) => {
        const cur = store.get(id)
        if (!cur) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
        if (cur.version !== expectedVersion) {
          throw new AuthErrorObject('AUTH/STALE_WRITE', {
            expected: expectedVersion,
            actual: cur.version,
          })
        }
        const next: AuthCredential.ICredential = {
          ...cur,
          secret: newSecret,
          version: cur.version + 1,
        }
        store.set(id, next)
        return next
      },
      patchMetadata: async (id, patch) => {
        const cur = store.get(id)
        if (!cur) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
        const next: AuthCredential.ICredential = {
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
        store.set(id, { ...cur, revokedAt: Date.now() })
      },
      delete: async (id) => {
        store.delete(id)
      },
      deleteByKind: async (identityId, kind) => {
        for (const c of store.values()) {
          if (c.identityId === identityId && c.kind === kind) store.delete(c.id)
        }
      },
      // OAuth refresh-reuse hook; memory walks every row (prod indexes by familyId).
      __familyRevoke: async (familyId: string) => {
        const now = Date.now()
        for (const c of store.values()) {
          if (c.kind !== 'oauth') continue
          const meta = c.metadata as { familyId?: string } | undefined
          if (meta?.familyId !== familyId) continue
          store.set(c.id, { ...c, revokedAt: c.revokedAt ?? now })
        }
      },
    }
  }

  // --- AuthOrg --------------------------------------------------------------

  private _buildOrgStore(): AuthOrg.IStore<OrgMeta> {
    return {
      getOrg: async (id) => this._orgs.get(id) ?? null,
      listOrgsForIdentity: async (identityId) => {
        const orgIds = new Set<string>()
        for (const m of this._memberships.values()) {
          if (m.identityId === identityId && !m.leftAt) orgIds.add(m.orgId)
        }
        return [...orgIds].map((id) => this._orgs.get(id)).filter((o): o is AuthOrg.IOrg<OrgMeta> => Boolean(o))
      },
      listMembers: async (orgId) => {
        return [...this._memberships.values()].filter((m) => m.orgId === orgId && !m.leftAt)
      },
      addMember: async (m) => {
        // CAS under JS single-threading; SQL uses partial UNIQUE on (orgId, identityId).
        const key = `${m.orgId}:${m.identityId}`
        const cur = this._memberships.get(key)
        if (cur && cur.leftAt === undefined) {
          throw new AuthErrorObject('AUTH/PROVIDER_FAILED', {
            providerId: 'orgs',
            detail: 'identity already a member of this org',
          })
        }
        const full: AuthOrg.IMembership = { ...m, joinedAt: Date.now() }
        this._memberships.set(key, full)
        return full
      },
      removeMember: async (orgId, identityId) => {
        const key = `${orgId}:${identityId}`
        const cur = this._memberships.get(key)
        if (cur) this._memberships.set(key, { ...cur, leftAt: Date.now() })
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
 * @template Profile - AuthIdentity profile shape.
 */
export const authMemoryStorage = <Profile = unknown>(): {
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
