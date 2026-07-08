/**
 * SQL-backed adapter built on the `SqlBridge.Me` contract.
 * Consumers implement the bridge against any ORM (Drizzle, Kysely,
 * Prisma, raw pg, mysql2, better-sqlite3, ...) and pass it to
 * `createSqlStores` to get back the typed Identity + Credential +
 * Session stores.
 *
 * The bridge is the single source of the persisted data: it returns rows
 * already in the canonical `Identity.Me` / `Credential.Me` / `Session.Me`
 * shape, and TypeScript enforces that at the bridge boundary. The store
 * layer does no runtime parsing or reshaping — it only owns write-time
 * concerns (id/timestamp/version generation, optimistic-lock patches,
 * metadata merge) and passes reads straight through.
 *
 * A reference Drizzle / pg implementation lives in
 * `src/adapters/drizzle/pg`.
 */

import { authUlid } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { Credential, Identity } from '~/core/types/identity'
import type { Session } from '~/core/types/session'
import type { SqlBridge } from './sql.types'

/**
 * Pick the credential a `findByHashedSecret` lookup should return from all
 * rows matching `(secret, kind)`: the freshest live row, or — when every
 * match is revoked — the freshest revoked row, so callers can tell "revoked"
 * apart from "never existed". Shared by every bridge so the semantics are
 * identical across dialects.
 */
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
 * Build the three Store impls from a `SqlBridge.Me`. The factory
 * does no schema migrations - consumers run their migration tool of
 * choice against the canonical column set captured by the row shapes.
 */
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
    findById: (id, ctx) => bridge.findById(id, ctx.tenantId),
    findByEmail: (email, ctx) => bridge.findByEmail(email, ctx.tenantId),
    findByProviderSub: (providerId, sub, ctx) => bridge.findByProviderSub(providerId, sub, ctx.tenantId),
    create: async (input, ctx) => {
      const now = new Date()
      const row: Identity.Me<Profile> = {
        id: authUlid(),
        tenantId: input.tenantId ?? ctx.tenantId ?? null,
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
    update: async (id, patch, expectedVersion, ctx) => {
      const sqlPatch: Partial<Omit<Identity.Me<Profile>, 'id'>> = {
        updatedAt: new Date(),
        version: expectedVersion + 1,
      }
      if (patch.profile !== undefined) sqlPatch.profile = patch.profile
      if (patch.providers !== undefined) sqlPatch.providers = patch.providers
      if (patch.emailVerified !== undefined) sqlPatch.emailVerified = patch.emailVerified
      if (patch.tenantId !== undefined) sqlPatch.tenantId = patch.tenantId
      if (patch.deletedAt !== undefined) sqlPatch.deletedAt = patch.deletedAt
      const next = await bridge.updateConditional(id, sqlPatch, expectedVersion, ctx.tenantId)
      if (!next) {
        throw new AuthError('AUTH_STALE_WRITE', { expected: expectedVersion, actual: -1 })
      }
      return next
    },
    softDelete: async (id, gracePeriodMs, ctx) => {
      await bridge.softDelete(id, new Date(Date.now() + gracePeriodMs), ctx.tenantId)
    },
    restore: async (id, ctx) => {
      const row = await bridge.restore(id, ctx.tenantId)
      if (!row) throw new AuthError('AUTH_UNAUTHENTICATED')
      return row
    },
    erase: async (id, ctx) => {
      await bridge.erase(id, ctx.tenantId)
    },
    link: async (identityId, link, ctx) => {
      await bridge.insertProviderLink(identityId, link.providerId, link.providerSub, link.addedAt, ctx.tenantId)
    },
    unlink: async (identityId, providerId, ctx) => {
      await bridge.deleteProviderLink(identityId, providerId, ctx.tenantId)
    },
    merge: async (survivorId, dupId, ctx) => {
      await bridge.merge(survivorId, dupId, ctx.tenantId)
    },
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
      if (!next) {
        throw new AuthError('AUTH_STALE_WRITE', { expected: expectedVersion, actual: -1 })
      }
      return next
    },
    patchMetadata: async (id, patch, ctx) => {
      // Read-modify-write keyed on version; one retry, then AUTH/STALE_WRITE.
      for (let attempt = 0; attempt < 2; attempt++) {
        const row = await bridge.findById(id, ctx.tenantId)
        if (!row) throw new AuthError('AUTH_UNAUTHENTICATED')
        const merged = { ...(row.metadata ?? {}), ...patch }
        const next = await bridge.updateConditional(
          id,
          { metadata: merged, version: row.version + 1 },
          row.version,
          ctx.tenantId,
        )
        if (next) return next
      }
      throw new AuthError('AUTH_STALE_WRITE', { expected: -1, actual: -1 })
    },
    revoke: async (id, ctx) => {
      await bridge.revoke(id, new Date(), ctx.tenantId)
    },
    delete: async (id, ctx) => {
      await bridge.delete(id, ctx.tenantId)
    },
    deleteByKind: async (identityId, kind, ctx) => {
      await bridge.deleteByKind(identityId, kind, ctx.tenantId)
    },
  }
}

function buildSessions(bridge: SqlBridge.Session<Session.Me>): Session.Store {
  return {
    create: async (s) => {
      // Fill the nullable columns the caller may have omitted, so the bridge
      // always receives a complete `Session.Me` row.
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
      await bridge.insert(row)
    },
    getByHash: (sidHash) => bridge.findByHash(sidHash),
    update: async (id, patch) => {
      const sqlPatch: Partial<Omit<Session.Me, 'id'>> = {}

      if (patch.identityId !== undefined) sqlPatch.identityId = patch.identityId
      if (patch.tenantId !== undefined) sqlPatch.tenantId = patch.tenantId
      if (patch.kind !== undefined) sqlPatch.kind = patch.kind
      if (patch.aal !== undefined) sqlPatch.aal = patch.aal
      if (patch.factors !== undefined) sqlPatch.factors = patch.factors
      if (patch.csrfHash !== undefined) sqlPatch.csrfHash = patch.csrfHash
      if (patch.ip !== undefined) sqlPatch.ip = patch.ip
      if (patch.userAgent !== undefined) sqlPatch.userAgent = patch.userAgent
      if (patch.fingerprint !== undefined) sqlPatch.fingerprint = patch.fingerprint
      if (patch.rotatedAt !== undefined) sqlPatch.rotatedAt = patch.rotatedAt
      if (patch.expiresAt !== undefined) sqlPatch.expiresAt = patch.expiresAt
      if (patch.absoluteExpiresAt !== undefined) sqlPatch.absoluteExpiresAt = patch.absoluteExpiresAt
      if (patch.fresh !== undefined) sqlPatch.fresh = patch.fresh
      if (patch.actingAs !== undefined) sqlPatch.actingAs = patch.actingAs

      const next = await bridge.update(id, sqlPatch)
      if (!next) {
        throw new AuthError('AUTH_SESSION_REVOKED', { reason: `session ${id} not found` })
      }

      return next
    },
    delete: async (id) => {
      await bridge.delete(id)
    },
    listByIdentity: (identityId) => bridge.listByIdentity(identityId),
    deleteAllForIdentity: async (identityId) => {
      await bridge.deleteAllForIdentity(identityId)
    },
    gc: async (now) => {
      const deleted = await bridge.deleteExpired(new Date(now))
      return { deleted }
    },
  }
}
