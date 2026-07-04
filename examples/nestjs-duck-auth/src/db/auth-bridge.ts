import type { AuthSqlBridge } from '@gentleduck/auth/adapters/sql'
import type { Column } from 'drizzle-orm'
import { and, eq, isNull, lt, sql } from 'drizzle-orm'
import type { BunSQLiteDatabase } from 'drizzle-orm/bun-sqlite'
import { authCredentials, authIdentities, authSessions } from './schema'

type RawCred = typeof authCredentials.$inferSelect
type RawSess = typeof authSessions.$inferSelect

function tw<T extends { tenantId: Column }>(t: T, tenantId: string | undefined) {
  return tenantId === undefined ? undefined : eq(t.tenantId, tenantId)
}

function parseProviderLinks(raw: string | null): Array<{ providerId: string; providerSub?: string; addedAt: number }> {
  try {
    return JSON.parse(raw ?? '[]')
  } catch {
    return []
  }
}

function toRow(row: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(row as Record<string, unknown>)) {
    if (v === undefined) out[k] = null
    else if (v instanceof Date) out[k] = v.getTime()
    else if (typeof v === 'boolean') out[k] = v ? 1 : 0
    else out[k] = v
  }
  return out
}

function toCredRow(r: RawCred): AuthSqlBridge.ICredentialRow {
  return {
    ...r,
    createdAt: new Date(r.createdAt),
    lastUsedAt: r.lastUsedAt != null ? new Date(r.lastUsedAt) : null,
    expiresAt: r.expiresAt != null ? new Date(r.expiresAt) : null,
    revokedAt: r.revokedAt != null ? new Date(r.revokedAt) : null,
  }
}

function toSessRow(r: RawSess): AuthSqlBridge.ISessionRow {
  return {
    ...r,
    createdAt: new Date(r.createdAt),
    rotatedAt: new Date(r.rotatedAt),
    expiresAt: new Date(r.expiresAt),
    absoluteExpiresAt: new Date(r.absoluteExpiresAt),
  }
}

export function createAuthDrizzleBunSqliteBridge<S extends Record<string, unknown>>(
  db: BunSQLiteDatabase<S>,
): AuthSqlBridge.IBridge {
  return {
    identities: {
      findById: async (id, tenantId) => {
        const rows = await db
          .select()
          .from(authIdentities)
          .where(and(eq(authIdentities.id, id), isNull(authIdentities.deletedAt)))
          .limit(1)
        const row = rows[0]
        if (!row) return null
        if (tenantId !== undefined && row.tenantId !== tenantId && row.tenantId !== null) return null
        return row
      },
      findByEmail: async (email, tenantId) => {
        const rows = db.all(
          sql`select * from auth_identities where json_extract(profile,'$.email')=${email} and deleted_at is null and (tenant_id is null or ${tenantId ?? null} is null or tenant_id=${tenantId ?? null}) limit 1`,
        )
        return (rows[0] as AuthSqlBridge.IIdentityRow) ?? null
      },
      findByProviderSub: async (providerId, sub, tenantId) => {
        const rows = db.all(
          sql`select i.* from auth_identities i,json_each(i.providers) j where json_extract(j.value,'$.providerId')=${providerId} and (json_extract(j.value,'$.providerSub')=${sub} or (${sub ?? null} is null and json_extract(j.value,'$.providerSub') is null)) and i.deleted_at is null and (i.tenant_id is null or ${tenantId ?? null} is null or i.tenant_id=${tenantId ?? null}) limit 1`,
        )
        return (rows[0] as AuthSqlBridge.IIdentityRow) ?? null
      },
      insert: async (row) => {
        await db.insert(authIdentities).values(row as never)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const result = await db
          .update(authIdentities)
          .set(patch as never)
          .where(
            and(eq(authIdentities.id, id), eq(authIdentities.version, expectedVersion), tw(authIdentities, tenantId)),
          )
          .returning()
        return (result[0] as AuthSqlBridge.IIdentityRow) ?? null
      },
      softDelete: async (id, deletedAt, tenantId) => {
        await db
          .update(authIdentities)
          .set({ deletedAt })
          .where(and(eq(authIdentities.id, id), tw(authIdentities, tenantId)))
      },
      restore: async (id, tenantId) => {
        const result = await db
          .update(authIdentities)
          .set({ deletedAt: null })
          .where(and(eq(authIdentities.id, id), tw(authIdentities, tenantId)))
          .returning()
        return (result[0] as AuthSqlBridge.IIdentityRow) ?? null
      },
      erase: async (id, tenantId) => {
        await db.delete(authCredentials).where(eq(authCredentials.identityId, id))
        await db.delete(authSessions).where(eq(authSessions.identityId, id))
        await db.delete(authIdentities).where(and(eq(authIdentities.id, id), tw(authIdentities, tenantId)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt, tenantId) => {
        const rows = await db
          .select({ providers: authIdentities.providers })
          .from(authIdentities)
          .where(and(eq(authIdentities.id, identityId), tw(authIdentities, tenantId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        const arr = parseProviderLinks(cur.providers)
        if (
          arr.some((p) => p.providerId === providerId && (providerSub === undefined || p.providerSub === providerSub))
        )
          return
        arr.push(providerSub === undefined ? { providerId, addedAt } : { providerId, providerSub, addedAt })
        await db
          .update(authIdentities)
          .set({ providers: JSON.stringify(arr) })
          .where(and(eq(authIdentities.id, identityId), tw(authIdentities, tenantId)))
      },
      deleteProviderLink: async (identityId, providerId, tenantId) => {
        const rows = await db
          .select({ providers: authIdentities.providers })
          .from(authIdentities)
          .where(and(eq(authIdentities.id, identityId), tw(authIdentities, tenantId)))
          .limit(1)
        const cur = rows[0]
        if (!cur) return
        await db
          .update(authIdentities)
          .set({
            providers: JSON.stringify(parseProviderLinks(cur.providers).filter((p) => p.providerId !== providerId)),
          })
          .where(and(eq(authIdentities.id, identityId), tw(authIdentities, tenantId)))
      },
      merge: async (survivorId, dupId, tenantId) => {
        await db.update(authCredentials).set({ identityId: survivorId }).where(eq(authCredentials.identityId, dupId))
        await db.update(authSessions).set({ identityId: survivorId }).where(eq(authSessions.identityId, dupId))
        await db.delete(authIdentities).where(and(eq(authIdentities.id, dupId), tw(authIdentities, tenantId)))
      },
    },
    credentials: {
      findById: async (id, tenantId) => {
        const rows = await db
          .select()
          .from(authCredentials)
          .where(and(eq(authCredentials.id, id), tw(authCredentials, tenantId)))
          .limit(1)
        return rows[0] ? toCredRow(rows[0]) : null
      },
      listByIdentity: async (identityId, kind, tenantId) => {
        const rows = await db
          .select()
          .from(authCredentials)
          .where(
            and(
              eq(authCredentials.identityId, identityId),
              kind ? eq(authCredentials.kind, kind) : undefined,
              tw(authCredentials, tenantId),
            ),
          )
        return rows.map(toCredRow)
      },
      findByProviderSub: async (_provider, _sub, _tenantId) => null,
      findByHashedSecret: async (secretHash, kind, tenantId) => {
        const rows = await db
          .select()
          .from(authCredentials)
          .where(
            and(eq(authCredentials.kind, kind), eq(authCredentials.secret, secretHash), tw(authCredentials, tenantId)),
          )
          .limit(1)
        return rows[0] ? toCredRow(rows[0]) : null
      },
      insert: async (row) => {
        await db.insert(authCredentials).values(toRow(row) as never)
      },
      updateConditional: async (id, patch, _expectedVersion, tenantId) => {
        const result = await db
          .update(authCredentials)
          .set(toRow(patch) as never)
          .where(and(eq(authCredentials.id, id), tw(authCredentials, tenantId)))
          .returning()
        return result[0] ? toCredRow(result[0]) : null
      },
      revoke: async (id, revokedAt, tenantId) => {
        await db
          .update(authCredentials)
          .set({ revokedAt })
          .where(and(eq(authCredentials.id, id), tw(authCredentials, tenantId)))
      },
      delete: async (id, tenantId) => {
        await db.delete(authCredentials).where(and(eq(authCredentials.id, id), tw(authCredentials, tenantId)))
      },
      deleteByKind: async (identityId, kind, tenantId) => {
        await db
          .delete(authCredentials)
          .where(
            and(
              eq(authCredentials.identityId, identityId),
              eq(authCredentials.kind, kind),
              tw(authCredentials, tenantId),
            ),
          )
      },
    },
    sessions: {
      insert: async (row) => {
        await db.insert(authSessions).values(toRow(row) as never)
      },
      findByHash: async (sidHash) => {
        const rows = await db.select().from(authSessions).where(eq(authSessions.id, sidHash)).limit(1)
        return rows[0] ? toSessRow(rows[0]) : null
      },
      update: async (id, patch) => {
        const result = await db
          .update(authSessions)
          .set(toRow(patch) as never)
          .where(eq(authSessions.id, id))
          .returning()
        return result[0] ? toSessRow(result[0]) : null
      },
      delete: async (id) => {
        await db.delete(authSessions).where(eq(authSessions.id, id))
      },
      listByIdentity: async (identityId) => {
        const rows = await db.select().from(authSessions).where(eq(authSessions.identityId, identityId))
        return rows.map(toSessRow)
      },
      deleteAllForIdentity: async (identityId) => {
        await db.delete(authSessions).where(eq(authSessions.identityId, identityId))
      },
      deleteExpired: async (now) => {
        const result = await db.delete(authSessions).where(lt(authSessions.expiresAt, now)).returning()
        return result.length
      },
    },
  }
}
