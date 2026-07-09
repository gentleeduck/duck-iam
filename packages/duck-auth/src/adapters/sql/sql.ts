import { authUlid } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { Identity } from '~/core/identities/identities.types'
import type { Session } from '~/core/sessions/sessions.types'
import type { Credential } from '~/core/types/identity'
import type { SqlBridge } from './sql.types'

/** Drops explicit undefined values from partial patches before passing to the bridge */
const stripUndefined = <T extends object>(obj: T): Partial<T> =>
  Object.fromEntries(Object.entries(obj).filter(([_, v]) => v !== undefined)) as Partial<T>

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

export function createSqlStores<Profile extends Identity.ProfileMetadataBase>(
  bridge: SqlBridge.Me<Profile>,
): {
  identities: Identity.Store<Profile>
  credentials: Credential.Store
  sessions: Session.Store
} {
  return {
    identities: buildIdentities<Profile>(bridge.identities),
    credentials: buildCredentials(bridge.credentials),
    sessions: buildSessions(bridge.sessions),
  }
}

function buildIdentities<Profile extends Identity.ProfileMetadataBase>(
  bridge: SqlBridge.Identity<Identity.Me<Profile>>,
): Identity.Store<Profile> {
  return {
    findById: (id) => bridge.findById(id),
    findByEmail: (email) => bridge.findByEmail(email),
    findByProviderSub: (providerId, sub) => bridge.findByProviderSub(providerId, sub),
    create: async (input) => {
      const now = new Date()
      const row: Identity.Me<Profile> = {
        id: authUlid(),
        profile: input.profile,
        providers: input.providers ?? [],
        version: 1,
        emailVerified: input.emailVerified ?? false,
        createdAt: now,
        updatedAt: now,
        deletedAt: null,
      }
      await bridge.insert(row)
      return row
    },
    update: async (id, patch, expectedVersion) => {
      const sqlPatch = {
        ...stripUndefined(patch),
        updatedAt: new Date(),
        version: expectedVersion + 1,
      }
      const next = await bridge.updateConditional(id, sqlPatch, expectedVersion)
      if (!next) throw new AuthError('AUTH_STALE_WRITE', { expected: expectedVersion, actual: -1 })
      return next
    },
    softDelete: (id, gracePeriodMs) => bridge.softDelete(id, new Date(Date.now() + gracePeriodMs)),
    restore: async (id) => {
      const row = await bridge.restore(id)
      if (!row) throw new AuthError('AUTH_UNAUTHENTICATED')
      return row
    },
    erase: (id) => bridge.erase(id),
    link: (identityId, link) => bridge.insertProviderLink(identityId, link.providerId, link.providerSub, link.addedAt),
    unlink: (identityId, providerId) => bridge.deleteProviderLink(identityId, providerId),
    merge: (survivorId, dupId) => bridge.merge(survivorId, dupId),
  }
}

function buildCredentials(bridge: SqlBridge.Credential<Credential.Me>): Credential.Store {
  return {
    findById: (id, ctx) => bridge.findById(id, ctx.tenantId),
    listByIdentity: (identityId, kind, ctx) => bridge.listByIdentity(identityId, kind, ctx.tenantId),
    findByProviderSub: (provider, sub, ctx) => bridge.findByProviderSub(provider, sub, ctx.tenantId),
    findByHashedSecret: (secretHash, kind, ctx) => bridge.findByHashedSecret(secretHash, kind, ctx.tenantId),
    upsert: async (input, ctx) => {
      const row: Credential.Me = {
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
        if (!row) throw new AuthError('AUTH_UNAUTHENTICATED')
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
  }
}

function buildSessions(bridge: SqlBridge.Session<Session.Me>): Session.Store {
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
    getByHash: (sidHash) => bridge.findByHash(sidHash),
    update: async (id, patch) => {
      const next = await bridge.update(id, stripUndefined(patch))
      if (!next) throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })
      return next
    },
    delete: (id) => bridge.delete(id),
    listByIdentity: (identityId) => bridge.listByIdentity(identityId),
    deleteAllForIdentity: (identityId) => bridge.deleteAllForIdentity(identityId),
    gc: async (now) => ({ deleted: await bridge.deleteExpired(new Date(now)) }),
  }
}
