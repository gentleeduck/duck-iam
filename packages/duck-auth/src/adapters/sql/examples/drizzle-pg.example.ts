// @ts-nocheck
/**
 * @packageDocumentation
 * Reference Drizzle ORM (Postgres) implementation of the SqlBridge
 * contract. Drop into your project, install the peerDeps, swap in your
 * own column / schema customizations, then hand the bridge to
 * `createSqlAuthStores`.
 *
 * NOT compiled by tsdown (skipped via the `.example.ts` suffix +
 * `@ts-nocheck` so consumers without `drizzle-orm` / `pg` installed
 * don't break their build). Copy the file, do not import it.
 *
 * Required peerDeps (consumer side):
 *   bun add drizzle-orm pg
 *   bun add -D drizzle-kit @types/pg
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { SqlBridge } from '@gentleduck/auth/adapters/sql'
import { and, eq, isNull, lt, sql } from 'drizzle-orm'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import { bigint, integer, pgTable, text } from 'drizzle-orm/pg-core'

// ---------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------

export const identitiesTable = pgTable('auth_identities', {
  id: text('id').primaryKey(),
  tenantId: text('tenant_id'),
  profile: text('profile'),
  providers: text('providers').notNull().default('[]'),
  version: integer('version').notNull().default(1),
  createdAt: bigint('created_at', { mode: 'number' }).notNull(),
  updatedAt: bigint('updated_at', { mode: 'number' }).notNull(),
  deletedAt: bigint('deleted_at', { mode: 'number' }),
})

export const credentialsTable = pgTable('auth_credentials', {
  id: text('id').primaryKey(),
  identityId: text('identity_id').notNull(),
  tenantId: text('tenant_id'),
  kind: text('kind').notNull(),
  secret: text('secret').notNull(),
  metadata: text('metadata'),
  version: integer('version').notNull().default(1),
  createdAt: bigint('created_at', { mode: 'number' }).notNull(),
  lastUsedAt: bigint('last_used_at', { mode: 'number' }),
  expiresAt: bigint('expires_at', { mode: 'number' }),
  revokedAt: bigint('revoked_at', { mode: 'number' }),
})

export const sessionsTable = pgTable('auth_sessions', {
  id: text('id').primaryKey(),
  identityId: text('identity_id'),
  tenantId: text('tenant_id'),
  kind: text('kind').notNull(),
  aal: integer('aal').notNull(),
  factors: text('factors').notNull().default('[]'),
  csrfHash: text('csrf_hash'),
  ip: text('ip'),
  userAgent: text('user_agent'),
  fingerprint: text('fingerprint'),
  createdAt: bigint('created_at', { mode: 'number' }).notNull(),
  rotatedAt: bigint('rotated_at', { mode: 'number' }).notNull(),
  expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
  absoluteExpiresAt: bigint('absolute_expires_at', { mode: 'number' }).notNull(),
  fresh: integer('fresh').notNull(),
  actingAs: text('acting_as'),
})

// ---------------------------------------------------------------------
// Bridge factory
// ---------------------------------------------------------------------

export function createDrizzlePgAuthBridge(db: NodePgDatabase): SqlBridge {
  /** Helper: scope a where clause by tenantId; null tenant matches the row's NULL. */
  function tenantWhere<T extends { tenantId: unknown }>(table: T, tenantId: string | undefined) {
    return tenantId === undefined ? undefined : eq(table.tenantId, tenantId)
  }

  return {
    identities: {
      findById: async (id, tenantId) => {
        const rows = await db
          .select()
          .from(identitiesTable)
          .where(and(eq(identitiesTable.id, id), isNull(identitiesTable.deletedAt)))
          .limit(1)
        const row = rows[0]
        if (!row) return null
        if (tenantId !== undefined && row.tenantId !== tenantId && row.tenantId !== null) return null
        return row
      },
      findByEmail: async (email, tenantId) => {
        // Profile is JSON-encoded; cheapest portable extraction is server-side json operators.
        const rows = await db.execute(
          sql`select * from ${identitiesTable}
              where (profile::jsonb)->>'email' = ${email}
                and deleted_at is null
                and (${tenantId ?? null}::text is null or tenant_id = ${tenantId ?? null}::text)
              limit 1`,
        )
        return (rows.rows[0] as never) ?? null
      },
      findByProviderSub: async (providerId, sub, tenantId) => {
        const rows = await db.execute(
          sql`select * from ${identitiesTable}
              where (providers::jsonb) @> ${sql.raw(JSON.stringify([{ providerId, providerSub: sub }]))}::jsonb
                and deleted_at is null
                and (${tenantId ?? null}::text is null or tenant_id = ${tenantId ?? null}::text)
              limit 1`,
        )
        return (rows.rows[0] as never) ?? null
      },
      insert: async (row) => {
        await db.insert(identitiesTable).values(row)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const result = await db
          .update(identitiesTable)
          .set(patch as never)
          .where(
            and(
              eq(identitiesTable.id, id),
              eq(identitiesTable.version, expectedVersion),
              tenantWhere(identitiesTable, tenantId),
            ),
          )
          .returning()
        return result[0] ?? null
      },
      softDelete: async (id, deletedAt, tenantId) => {
        await db
          .update(identitiesTable)
          .set({ deletedAt })
          .where(and(eq(identitiesTable.id, id), tenantWhere(identitiesTable, tenantId)))
      },
      restore: async (id, tenantId) => {
        const result = await db
          .update(identitiesTable)
          .set({ deletedAt: null })
          .where(and(eq(identitiesTable.id, id), tenantWhere(identitiesTable, tenantId)))
          .returning()
        return result[0] ?? null
      },
      erase: async (id, tenantId) => {
        await db.delete(credentialsTable).where(eq(credentialsTable.identityId, id))
        await db.delete(sessionsTable).where(eq(sessionsTable.identityId, id))
        await db.delete(identitiesTable).where(and(eq(identitiesTable.id, id), tenantWhere(identitiesTable, tenantId)))
      },
      insertProviderLink: async (identityId, providerId, providerSub, addedAt, _tenantId) => {
        const newLink = { providerId, providerSub, addedAt }
        await db.execute(
          sql`update ${identitiesTable}
              set providers = (
                select jsonb_agg(distinct elem)
                from jsonb_array_elements(providers::jsonb || ${sql.raw(JSON.stringify([newLink]))}::jsonb) elem
              )::text
              where id = ${identityId}`,
        )
      },
      deleteProviderLink: async (identityId, providerId, _tenantId) => {
        await db.execute(
          sql`update ${identitiesTable}
              set providers = (
                select coalesce(jsonb_agg(elem), '[]'::jsonb)::text
                from jsonb_array_elements(providers::jsonb) elem
                where (elem->>'providerId') != ${providerId}
              )
              where id = ${identityId}`,
        )
      },
      merge: async (survivorId, dupId, _tenantId) => {
        await db.update(credentialsTable).set({ identityId: survivorId }).where(eq(credentialsTable.identityId, dupId))
        await db.update(sessionsTable).set({ identityId: survivorId }).where(eq(sessionsTable.identityId, dupId))
        await db.delete(identitiesTable).where(eq(identitiesTable.id, dupId))
      },
    },
    credentials: {
      findById: async (id, tenantId) => {
        const rows = await db
          .select()
          .from(credentialsTable)
          .where(and(eq(credentialsTable.id, id), tenantWhere(credentialsTable, tenantId)))
          .limit(1)
        return rows[0] ?? null
      },
      listByIdentity: async (identityId, kind, tenantId) => {
        const where = [
          eq(credentialsTable.identityId, identityId),
          ...(kind ? [eq(credentialsTable.kind, kind)] : []),
          ...(tenantId ? [eq(credentialsTable.tenantId, tenantId)] : []),
        ]
        return db
          .select()
          .from(credentialsTable)
          .where(and(...where))
      },
      findByProviderSub: async (provider, sub, _tenantId) => {
        const rows = await db.execute(
          sql`select * from ${credentialsTable}
              where (metadata::jsonb)->>'provider' = ${provider}
                and (metadata::jsonb)->>'sub' = ${sub}
              limit 1`,
        )
        return (rows.rows[0] as never) ?? null
      },
      findByHashedSecret: async (secretHash, kind, tenantId) => {
        const rows = await db
          .select()
          .from(credentialsTable)
          .where(
            and(
              eq(credentialsTable.secret, secretHash),
              eq(credentialsTable.kind, kind),
              tenantWhere(credentialsTable, tenantId),
            ),
          )
          .limit(1)
        return rows[0] ?? null
      },
      insert: async (row) => {
        await db.insert(credentialsTable).values(row)
      },
      updateConditional: async (id, patch, expectedVersion, tenantId) => {
        const result = await db
          .update(credentialsTable)
          .set(patch as never)
          .where(
            and(
              eq(credentialsTable.id, id),
              eq(credentialsTable.version, expectedVersion),
              tenantWhere(credentialsTable, tenantId),
            ),
          )
          .returning()
        return result[0] ?? null
      },
      revoke: async (id, revokedAt, tenantId) => {
        await db
          .update(credentialsTable)
          .set({ revokedAt })
          .where(and(eq(credentialsTable.id, id), tenantWhere(credentialsTable, tenantId)))
      },
      delete: async (id, tenantId) => {
        await db
          .delete(credentialsTable)
          .where(and(eq(credentialsTable.id, id), tenantWhere(credentialsTable, tenantId)))
      },
      deleteByKind: async (identityId, kind, tenantId) => {
        await db
          .delete(credentialsTable)
          .where(
            and(
              eq(credentialsTable.identityId, identityId),
              eq(credentialsTable.kind, kind),
              tenantWhere(credentialsTable, tenantId),
            ),
          )
      },
    },
    sessions: {
      insert: async (row) => {
        await db.insert(sessionsTable).values(row)
      },
      findByHash: async (sidHash) => {
        const rows = await db.select().from(sessionsTable).where(eq(sessionsTable.id, sidHash)).limit(1)
        return rows[0] ?? null
      },
      update: async (id, patch) => {
        const result = await db
          .update(sessionsTable)
          .set(patch as never)
          .where(eq(sessionsTable.id, id))
          .returning()
        return result[0] ?? null
      },
      delete: async (id) => {
        await db.delete(sessionsTable).where(eq(sessionsTable.id, id))
      },
      listByIdentity: async (identityId) => {
        return db.select().from(sessionsTable).where(eq(sessionsTable.identityId, identityId))
      },
      deleteAllForIdentity: async (identityId) => {
        await db.delete(sessionsTable).where(eq(sessionsTable.identityId, identityId))
      },
      deleteExpired: async (now) => {
        const result = await db.delete(sessionsTable).where(lt(sessionsTable.absoluteExpiresAt, now)).returning()
        return result.length
      },
    },
  }
}

// ---------------------------------------------------------------------
// Wire-up (replace with your own AuthRoot config)
// ---------------------------------------------------------------------
//
// import { drizzle } from 'drizzle-orm/node-postgres'
// import { Pool } from 'pg'
// import { createSqlAuthStores } from '@gentleduck/auth/adapters/sql'
//
// const pool = new Pool({ connectionString: process.env.DATABASE_URL! })
// const db = drizzle(pool, { schema: { identitiesTable, credentialsTable, sessionsTable } })
// const bridge = createDrizzlePgAuthBridge(db)
// const stores = createSqlAuthStores<MyProfile>(bridge)
//
// new AuthRoot({ stores, ... })
