/**
 * SQL-backed adapter built on the `SqlBridge.IBridge` contract.
 * Consumers implement the bridge against any ORM (Drizzle, Kysely,
 * Prisma, raw pg, mysql2, better-sqlite3, ...) and pass it to
 * `createSqlAuthStores` to get back the typed Identity + Credential +
 * Session stores.
 *
 * A reference Drizzle / pg implementation lives in
 * `src/adapters/sql/examples/drizzle-pg.example.ts`.
 */

import { randomToken } from '../../core/crypto'
import { AuthErrorObject } from '../../core/errors'
import type { Credential } from '../../core/types/credential'
import type { Identity } from '../../core/types/identity'
import type { Session } from '../../core/types/session'
import type { SqlBridge } from './bridge'

export type { SqlBridge } from './bridge'

/**
 * Build the three IStore impls from a `SqlBridge.IBridge`. The factory
 * does no schema migrations - consumers run their migration tool of
 * choice against the canonical column set captured by the row shapes.
 */
export function createSqlAuthStores<Profile = unknown>(
  bridge: SqlBridge.IBridge,
): {
  identities: Identity.IStore<Profile>
  credentials: Credential.IStore
  sessions: Session.IStore
} {
  return {
    identities: buildIdentities<Profile>(bridge.identities),
    credentials: buildCredentials(bridge.credentials),
    sessions: buildSessions(bridge.sessions),
  }
}

function buildIdentities<Profile>(bridge: SqlBridge.IIdentity): Identity.IStore<Profile> {
  return {
    findById: async (id, ctx) => parseIdentity<Profile>(await bridge.findById(id, ctx.tenantId)),
    findByEmail: async (email, ctx) => parseIdentity<Profile>(await bridge.findByEmail(email, ctx.tenantId)),
    findByProviderSub: async (providerId, sub, ctx) =>
      parseIdentity<Profile>(await bridge.findByProviderSub(providerId, sub, ctx.tenantId)),
    create: async (input, ctx) => {
      const now = Date.now()
      const row: SqlBridge.IIdentityRow = {
        id: randomToken(16),
        tenantId: input.tenantId ?? ctx.tenantId ?? null,
        profile: input.profile === undefined ? null : JSON.stringify(input.profile),
        providers: JSON.stringify(input.providers ?? []),
        version: 1,
        createdAt: now,
        updatedAt: now,
        deletedAt: null,
      }
      await bridge.insert(row)
      return parseIdentityStrict<Profile>(row)
    },
    update: async (id, patch, expectedVersion, ctx) => {
      const sqlPatch: Partial<Omit<SqlBridge.IIdentityRow, 'id'>> = {
        updatedAt: Date.now(),
        version: expectedVersion + 1,
      }
      if (patch.profile !== undefined) sqlPatch.profile = JSON.stringify(patch.profile)
      if (patch.providers !== undefined) sqlPatch.providers = JSON.stringify(patch.providers)
      if (patch.tenantId !== undefined) sqlPatch.tenantId = patch.tenantId
      if (patch.deletedAt !== undefined) sqlPatch.deletedAt = patch.deletedAt
      const next = await bridge.updateConditional(id, sqlPatch, expectedVersion, ctx.tenantId)
      if (!next) {
        throw new AuthErrorObject('AUTH/STALE_WRITE', { expected: expectedVersion, actual: -1 })
      }
      return parseIdentityStrict<Profile>(next)
    },
    softDelete: async (id, gracePeriodMs, ctx) => {
      await bridge.softDelete(id, Date.now() + gracePeriodMs, ctx.tenantId)
    },
    restore: async (id, ctx) => {
      const row = await bridge.restore(id, ctx.tenantId)
      if (!row) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
      return parseIdentityStrict<Profile>(row)
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

function buildCredentials(bridge: SqlBridge.ICredential): Credential.IStore {
  return {
    findById: async (id, ctx) => parseCredential(await bridge.findById(id, ctx.tenantId)),
    listByIdentity: async (identityId, kind, ctx) => {
      const rows = await bridge.listByIdentity(identityId, kind, ctx.tenantId)
      return rows.map(parseCredential).filter((c): c is Credential.ICredential => c !== null)
    },
    findByProviderSub: async (provider, sub, ctx) =>
      parseCredential(await bridge.findByProviderSub(provider, sub, ctx.tenantId)),
    findByHashedSecret: async (secretHash, kind, ctx) =>
      parseCredential(await bridge.findByHashedSecret(secretHash, kind, ctx.tenantId)),
    upsert: async (input, ctx) => {
      const now = Date.now()
      const row: SqlBridge.ICredentialRow = {
        id: randomToken(16),
        identityId: input.identityId,
        tenantId: input.tenantId ?? ctx.tenantId ?? null,
        kind: input.kind,
        secret: input.secret,
        metadata: input.metadata === undefined ? null : JSON.stringify(input.metadata),
        version: 1,
        createdAt: now,
        lastUsedAt: input.lastUsedAt ?? null,
        expiresAt: input.expiresAt ?? null,
        revokedAt: input.revokedAt ?? null,
      }
      await bridge.insert(row)
      return parseCredentialStrict(row)
    },
    rotate: async (id, newSecret, expectedVersion, ctx) => {
      const next = await bridge.updateConditional(
        id,
        { secret: newSecret, version: expectedVersion + 1, lastUsedAt: Date.now() },
        expectedVersion,
        ctx.tenantId,
      )
      if (!next) {
        throw new AuthErrorObject('AUTH/STALE_WRITE', { expected: expectedVersion, actual: -1 })
      }
      return parseCredentialStrict(next)
    },
    patchMetadata: async (id, patch, ctx) => {
      // Read-modify-write keyed on version; one retry, then AUTH/STALE_WRITE.
      for (let attempt = 0; attempt < 2; attempt++) {
        const row = await bridge.findById(id, ctx.tenantId)
        if (!row) throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
        const meta = row.metadata === null ? {} : (JSON.parse(row.metadata) as Record<string, unknown>)
        const merged = { ...meta, ...patch }
        const next = await bridge.updateConditional(
          id,
          { metadata: JSON.stringify(merged), version: row.version + 1 },
          row.version,
          ctx.tenantId,
        )
        if (next) return parseCredentialStrict(next)
      }
      throw new AuthErrorObject('AUTH/STALE_WRITE', { detail: 'patchMetadata: lost two consecutive races' })
    },
    revoke: async (id, ctx) => {
      await bridge.revoke(id, Date.now(), ctx.tenantId)
    },
    delete: async (id, ctx) => {
      await bridge.delete(id, ctx.tenantId)
    },
    deleteByKind: async (identityId, kind, ctx) => {
      await bridge.deleteByKind(identityId, kind, ctx.tenantId)
    },
  }
}

function buildSessions(bridge: SqlBridge.ISession): Session.IStore {
  return {
    create: async (s) => {
      const row: SqlBridge.ISessionRow = {
        id: s.id,
        identityId: s.identityId,
        tenantId: s.tenantId ?? null,
        kind: s.kind,
        aal: s.aal,
        factors: JSON.stringify(s.factors),
        csrfHash: s.csrfHash ?? null,
        ip: s.ip ?? null,
        userAgent: s.userAgent ?? null,
        fingerprint: s.fingerprint ?? null,
        createdAt: s.createdAt,
        rotatedAt: s.rotatedAt,
        expiresAt: s.expiresAt,
        absoluteExpiresAt: s.absoluteExpiresAt,
        fresh: s.fresh ? 1 : 0,
        actingAs: s.actingAs === undefined ? null : JSON.stringify(s.actingAs),
      }
      await bridge.insert(row)
    },
    getByHash: async (sidHash) => parseSession(await bridge.findByHash(sidHash)),
    update: async (id, patch) => {
      const sqlPatch: Partial<Omit<SqlBridge.ISessionRow, 'id'>> = {}
      if (patch.identityId !== undefined) sqlPatch.identityId = patch.identityId
      if (patch.tenantId !== undefined) sqlPatch.tenantId = patch.tenantId
      if (patch.kind !== undefined) sqlPatch.kind = patch.kind
      if (patch.aal !== undefined) sqlPatch.aal = patch.aal
      if (patch.factors !== undefined) sqlPatch.factors = JSON.stringify(patch.factors)
      if (patch.csrfHash !== undefined) sqlPatch.csrfHash = patch.csrfHash
      if (patch.ip !== undefined) sqlPatch.ip = patch.ip
      if (patch.userAgent !== undefined) sqlPatch.userAgent = patch.userAgent
      if (patch.fingerprint !== undefined) sqlPatch.fingerprint = patch.fingerprint
      if (patch.rotatedAt !== undefined) sqlPatch.rotatedAt = patch.rotatedAt
      if (patch.expiresAt !== undefined) sqlPatch.expiresAt = patch.expiresAt
      if (patch.absoluteExpiresAt !== undefined) sqlPatch.absoluteExpiresAt = patch.absoluteExpiresAt
      if (patch.fresh !== undefined) sqlPatch.fresh = patch.fresh ? 1 : 0
      if (patch.actingAs !== undefined) {
        sqlPatch.actingAs = patch.actingAs === null ? null : JSON.stringify(patch.actingAs)
      }
      const next = await bridge.update(id, sqlPatch)
      if (!next) {
        throw new AuthErrorObject('AUTH/SESSION_REVOKED', { reason: `session ${id} not found` })
      }
      return parseSessionStrict(next)
    },
    delete: async (id) => {
      await bridge.delete(id)
    },
    listByIdentity: async (identityId) => {
      const rows = await bridge.listByIdentity(identityId)
      return rows.map(parseSessionStrict)
    },
    deleteAllForIdentity: async (identityId) => {
      await bridge.deleteAllForIdentity(identityId)
    },
    gc: async (now) => {
      const deleted = await bridge.deleteExpired(now)
      return { deleted }
    },
  }
}

function parseIdentity<Profile>(row: SqlBridge.IIdentityRow | null): Identity.IIdentity<Profile> | null {
  if (!row) return null
  return parseIdentityStrict<Profile>(row)
}

function parseIdentityStrict<Profile>(row: SqlBridge.IIdentityRow): Identity.IIdentity<Profile> {
  const out: Identity.IIdentity<Profile> = {
    id: row.id,
    providers: JSON.parse(row.providers) as Identity.ProviderLink[],
    version: row.version,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  }
  if (row.tenantId !== null) out.tenantId = row.tenantId
  if (row.profile !== null) out.profile = JSON.parse(row.profile) as Profile
  if (row.deletedAt !== null) out.deletedAt = row.deletedAt
  return out
}

function parseCredential(row: SqlBridge.ICredentialRow | null): Credential.ICredential | null {
  if (!row) return null
  return parseCredentialStrict(row)
}

function parseCredentialStrict(row: SqlBridge.ICredentialRow): Credential.ICredential {
  const out: Credential.ICredential = {
    id: row.id,
    identityId: row.identityId,
    kind: row.kind as Credential.Kind,
    secret: row.secret,
    version: row.version,
    createdAt: row.createdAt,
  }
  if (row.tenantId !== null) out.tenantId = row.tenantId
  if (row.metadata !== null) out.metadata = JSON.parse(row.metadata) as Record<string, unknown>
  if (row.lastUsedAt !== null) out.lastUsedAt = row.lastUsedAt
  if (row.expiresAt !== null) out.expiresAt = row.expiresAt
  if (row.revokedAt !== null) out.revokedAt = row.revokedAt
  return out
}

function parseSession(row: SqlBridge.ISessionRow | null): Session.ISession | null {
  if (!row) return null
  return parseSessionStrict(row)
}

function parseSessionStrict(row: SqlBridge.ISessionRow): Session.ISession {
  const session: Session.ISession = {
    id: row.id,
    identityId: row.identityId,
    kind: row.kind as Session.Kind,
    aal: row.aal as Session.AAL,
    factors: JSON.parse(row.factors) as Session.Factor[],
    createdAt: row.createdAt,
    rotatedAt: row.rotatedAt,
    expiresAt: row.expiresAt,
    absoluteExpiresAt: row.absoluteExpiresAt,
    fresh: row.fresh === 1,
  }
  if (row.tenantId !== null) session.tenantId = row.tenantId
  if (row.csrfHash !== null) session.csrfHash = row.csrfHash
  if (row.ip !== null) session.ip = row.ip
  if (row.userAgent !== null) session.userAgent = row.userAgent
  if (row.fingerprint !== null) session.fingerprint = row.fingerprint
  if (row.actingAs !== null) session.actingAs = JSON.parse(row.actingAs) as Session.ActingAs
  return session
}
