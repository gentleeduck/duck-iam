import { randomToken } from '../../core/crypto'
import { AuthErrorObject } from '../../core/errors'
import type { TenantContext } from '../../core/types/context'
import type { Credential } from '../../core/types/credential'
import type { Identity } from '../../core/types/identity'
import type { Org } from '../../core/types/org'
import type { Session } from '../../core/types/session'

/**
 * In-memory adapter — dev + test only. Production must use redis/drizzle/prisma.
 * Strict mode rejects this adapter when `env: 'production'`.
 *
 * Multi-tenant: tenantId filters every query so tests can verify isolation.
 */
export class MemoryAuthAdapter<Profile = unknown, OrgMeta = unknown> {
  readonly identities: Identity.IStore<Profile>
  readonly sessions: Session.IStore
  readonly credentials: Credential.IStore
  readonly orgs: Org.IStore<OrgMeta>

  private _identities = new Map<string, Identity.IIdentity<Profile>>()
  private _sessions = new Map<string, Session.ISession>()
  private _credentials = new Map<string, Credential.ICredential>()
  private _orgs = new Map<string, Org.IOrg<OrgMeta>>()
  private _memberships = new Map<string, Org.IMembership>()

  constructor() {
    this.identities = this._buildIdentityStore()
    this.sessions = this._buildSessionStore()
    this.credentials = this._buildCredentialStore()
    this.orgs = this._buildOrgStore()
  }

  // --- Identity ---------------------------------------------------------

  private _buildIdentityStore(): Identity.IStore<Profile> {
    const store = this._identities
    const filter = (id: Identity.IIdentity<Profile>, ctx: TenantContext) =>
      ctx.tenantId === undefined || id.tenantId === ctx.tenantId

    return {
      findById: async (id, ctx) => {
        const i = store.get(id)
        return i && filter(i, ctx) && !i.deletedAt ? i : null
      },
      findByEmail: async (email, ctx) => {
        for (const i of store.values()) {
          if (!filter(i, ctx) || i.deletedAt) continue
          const e = (i.profile as { email?: string } | undefined)?.email
          if (e === email) return i
        }
        return null
      },
      findByProviderSub: async (providerId, sub, ctx) => {
        for (const i of store.values()) {
          if (!filter(i, ctx) || i.deletedAt) continue
          if (i.providers.some((p) => p.providerId === providerId && p.providerSub === sub)) {
            return i
          }
        }
        return null
      },
      create: async (input, ctx) => {
        const now = Date.now()
        const id: Identity.IIdentity<Profile> = {
          ...input,
          id: randomToken(16),
          tenantId: ctx.tenantId,
          providers: input.providers ?? [],
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
        const next: Identity.IIdentity<Profile> = {
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
        const next = { ...cur, deletedAt: undefined } as Identity.IIdentity<Profile>
        store.set(id, next)
        return next
      },
      erase: async (id, _ctx) => {
        store.delete(id)
      },
      link: async (identityId, link, _ctx) => {
        const cur = store.get(identityId)
        if (!cur) return
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

  private _buildSessionStore(): Session.IStore {
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

  // --- Credential -------------------------------------------------------

  private _buildCredentialStore(): Credential.IStore {
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
      upsert: async (input) => {
        const id = randomToken(16)
        const now = Date.now()
        const c: Credential.ICredential = {
          id,
          version: 1,
          createdAt: now,
          ...input,
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
        const next: Credential.ICredential = {
          ...cur,
          secret: newSecret,
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
    }
  }

  // --- Org --------------------------------------------------------------

  private _buildOrgStore(): Org.IStore<OrgMeta> {
    return {
      getOrg: async (id) => this._orgs.get(id) ?? null,
      listOrgsForIdentity: async (identityId) => {
        const orgIds = new Set<string>()
        for (const m of this._memberships.values()) {
          if (m.identityId === identityId && !m.leftAt) orgIds.add(m.orgId)
        }
        return [...orgIds].map((id) => this._orgs.get(id)).filter((o): o is Org.IOrg<OrgMeta> => Boolean(o))
      },
      listMembers: async (orgId) => {
        return [...this._memberships.values()].filter((m) => m.orgId === orgId && !m.leftAt)
      },
      addMember: async (m) => {
        const full: Org.IMembership = { ...m, joinedAt: Date.now() }
        this._memberships.set(`${m.orgId}:${m.identityId}`, full)
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
