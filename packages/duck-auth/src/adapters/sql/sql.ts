import { type Batch, batchResult } from '~/core/batch'
import type { Credential } from '~/core/credentials/credentials.types'
import { authUlid } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
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

export function createSqlStores<Profile extends Identities.ProfileMetadataBase>(
  bridge: SqlBridge.Me<Profile>,
): {
  identities: Identities.Store<Profile>
  credentials: Credential.Store
  sessions: Sessions.Store
} {
  const identities = buildIdentities<Profile>(bridge.identities)
  const credentials = buildCredentials(bridge.credentials)
  const sessions = buildSessions(bridge.sessions)

  // One bridge-level rebind covers all three stores: re-make the bridge against
  // the caller's client, then rebuild the stores from it. Adapters therefore
  // implement `withClient` once, not once per store.
  const rebind = bridge.withClient
  if (rebind) {
    identities.withClient = (client) => createSqlStores<Profile>(rebind(client)).identities
    credentials.withClient = (client) => createSqlStores<Profile>(rebind(client)).credentials
    sessions.withClient = (client) => createSqlStores<Profile>(rebind(client)).sessions
  }

  return { identities, credentials, sessions }
}

/**
 * Turns "ids I asked for" plus "ids the statement actually touched" into
 * per-row outcomes in input order.
 *
 * An id the statement did not touch is `not-found` - which is exactly what a
 * `WHERE id = ANY($1)` matching fewer rows than it was given means.
 */
function outcomesFromAffected(requested: readonly string[], affected: readonly string[]): Batch.Result {
  const hit = new Set(affected)
  return batchResult(
    requested.map((id) =>
      hit.has(id)
        ? { id, ok: true as const, value: undefined }
        : { id, ok: false as const, reason: 'not-found' as const },
    ),
  )
}

/** Outcome id for a provider link; mirrors the facet's key so outcomes line up. */
function linkKey(identityId: string, providerId: string): string {
  return `${identityId} ${providerId}`
}

function buildIdentities<Profile extends Identities.ProfileMetadataBase>(
  bridge: SqlBridge.Identity<Identities.Me<Profile>>,
): Identities.Store<Profile> {
  // Hoisted so the `&&` guard below narrows a `const` the closure captures.
  // Reading `bridge.x` again inside the closure would be `x | undefined` all
  // over again, and the only way back would be a `!` the type system cannot
  // check.
  //
  // Bound, not destructured: `SqlBridge.Identity` is an interface, so a caller
  // may implement it as a class, and a bare `const { x } = bridge` would drop
  // the `this` its methods need.
  const softDeleteManyReturningIds = bridge.softDeleteManyReturningIds?.bind(bridge)
  const eraseManyReturningIds = bridge.eraseManyReturningIds?.bind(bridge)
  const restoreManyReturning = bridge.restoreManyReturning?.bind(bridge)
  const updateProfileManyReturning = bridge.updateProfileManyReturning?.bind(bridge)
  const insertProviderLinks = bridge.insertProviderLinks?.bind(bridge)
  const deleteProviderLinks = bridge.deleteProviderLinks?.bind(bridge)
  return {
    findById: (id) => bridge.findById(id),
    findByEmail: (email) => bridge.findByEmail(email),
    findByProviderSub: (providerId, sub) => bridge.findByProviderSub(providerId, sub),
    create: async (input) => {
      const now = new Date()
      const row: Identities.Me<Profile> = {
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

    ...(softDeleteManyReturningIds && {
      softDeleteMany: async (ids: readonly string[], gracePeriodMs: number) =>
        outcomesFromAffected(ids, await softDeleteManyReturningIds(ids, new Date(Date.now() + gracePeriodMs))),
    }),

    ...(eraseManyReturningIds && {
      eraseMany: async (ids: readonly string[]) => outcomesFromAffected(ids, await eraseManyReturningIds(ids)),
    }),

    ...(restoreManyReturning && {
      restoreMany: async (ids: readonly string[]) => {
        const rows = await restoreManyReturning(ids)
        const byId = new Map(rows.map((row) => [row.id, row]))
        return batchResult(
          ids.map((id) => {
            const row = byId.get(id)
            return row
              ? { id, ok: true as const, value: row }
              : { id, ok: false as const, reason: 'not-found' as const }
          }),
        )
      },
    }),

    ...(updateProfileManyReturning && {
      updateProfileMany: async (rows: readonly { id: string; profile: Profile; expectedVersion: number }[]) => {
        const updated = await updateProfileManyReturning(
          rows.map((r) => ({
            expectedVersion: r.expectedVersion,
            id: r.id,
            patch: { profile: r.profile, updatedAt: new Date(), version: r.expectedVersion + 1 },
          })),
        )
        const byId = new Map(updated.map((row) => [row.id, row]))
        // A requested id missing from the response is `stale-write`, not
        // `not-found`: the facet already proved the row exists, so the only way
        // the conditional update matched nothing is a version mismatch.
        return batchResult(
          rows.map((r) => {
            const row = byId.get(r.id)
            return row
              ? { id: r.id, ok: true as const, value: row }
              : { id: r.id, ok: false as const, reason: 'stale-write' as const }
          }),
        )
      },
    }),

    ...(insertProviderLinks && {
      linkMany: async (links: readonly { identityId: string; link: Identities.ProviderLink }[]) =>
        outcomesFromAffected(
          links.map((l) => linkKey(l.identityId, l.link.providerId)),
          await insertProviderLinks(
            links.map((l) => ({
              addedAt: l.link.addedAt,
              identityId: l.identityId,
              providerId: l.link.providerId,
              providerSub: l.link.providerSub,
            })),
          ),
        ),
    }),

    ...(deleteProviderLinks && {
      unlinkMany: async (links: readonly { identityId: string; providerId: string }[]) =>
        outcomesFromAffected(
          links.map((l) => linkKey(l.identityId, l.providerId)),
          await deleteProviderLinks([...links]),
        ),
    }),
  }
}

function buildCredentials(bridge: SqlBridge.Credential<Credential.Me>): Credential.Store {
  // Bound, not destructured - see the note in `buildIdentities`.
  const deleteByIdentitiesReturningIds = bridge.deleteByIdentitiesReturningIds?.bind(bridge)
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

    ...(deleteByIdentitiesReturningIds && {
      deleteByIdentities: async (identityIds: readonly string[], ctx: TenantContext) =>
        outcomesFromAffected(identityIds, await deleteByIdentitiesReturningIds(identityIds, ctx.tenantId)),
    }),
  }
}

function buildSessions(bridge: SqlBridge.Session<Sessions.Me>): Sessions.Store {
  // Bound, not destructured - see the note in `buildIdentities`.
  const deleteAllForIdentitiesReturningIds = bridge.deleteAllForIdentitiesReturningIds?.bind(bridge)
  const deleteManyReturningIds = bridge.deleteManyReturningIds?.bind(bridge)
  const listByIdentities = bridge.listByIdentities?.bind(bridge)
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

    ...(deleteAllForIdentitiesReturningIds && {
      deleteAllForIdentities: async (identityIds: readonly string[]) =>
        outcomesFromAffected(identityIds, await deleteAllForIdentitiesReturningIds(identityIds)),
    }),

    ...(deleteManyReturningIds && {
      deleteMany: async (ids: readonly string[]) => outcomesFromAffected(ids, await deleteManyReturningIds(ids)),
    }),

    ...(listByIdentities && {
      listByIdentities: (identityIds: readonly string[]) => listByIdentities(identityIds),
    }),
  }
}
