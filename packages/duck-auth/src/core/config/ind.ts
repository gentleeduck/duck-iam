import { and, eq, inArray } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { integer, jsonb, pgTable, text } from 'drizzle-orm/pg-core'
import { Pool } from 'pg'
import { drizzlePgStorage } from '~/adapters/drizzle/pg'
import { AuthMemoryLimiter } from '~/limiters/memory'
import { passwordProvider } from '~/providers/password'
import { Argon2idHasher } from '~/providers/password/hashers/argon2.hasher'
import { ScryptHasher } from '~/providers/password/hashers/scrypt.hasher'
import { AuthEngine } from '../engine'
import { InMemoryEvents } from '../events'
import { AuthCookieTransport } from '../transport'
import type { Org } from '../types/identity'
import { createAuth } from './config'

// ---------------------------------------------------------------------------
// 1. Define org tables (add to your drizzle schema file)
// ---------------------------------------------------------------------------

interface OrgMeta {
  plan: 'free' | 'pro' | 'enterprise'
  avatarUrl?: string
}

const orgsTable = pgTable('orgs', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  domain: text('domain'),
  metadata: jsonb('metadata').$type<OrgMeta>(),
  createdAt: integer('created_at').notNull(),
})

const orgMembersTable = pgTable('org_members', {
  orgId: text('org_id')
    .notNull()
    .references(() => orgsTable.id, { onDelete: 'cascade' }),
  identityId: text('identity_id').notNull(),
  roles: text('roles').array().notNull().default([]),
  invitedAt: integer('invited_at'),
  joinedAt: integer('joined_at').notNull(),
  leftAt: integer('left_at'),
})

// ---------------------------------------------------------------------------
// 2. Implement Org.Store<OrgMeta> against those tables
// ---------------------------------------------------------------------------

function buildOrgStore(db: ReturnType<typeof drizzle>): Org.Store<OrgMeta> {
  return {
    async getOrg(id, _ctx) {
      const rows = await db.select().from(orgsTable).where(eq(orgsTable.id, id)).limit(1)
      const row = rows[0]
      if (!row) return null
      return {
        id: row.id,
        name: row.name,
        domain: row.domain ?? null,
        metadata: row.metadata ?? null,
        createdAt: new Date(row.createdAt),
      }
    },

    async listOrgsForIdentity(identityId, _ctx) {
      const members = await db
        .select()
        .from(orgMembersTable)
        .where(and(eq(orgMembersTable.identityId, identityId)))
      if (!members.length) return []
      const orgIds = members.map((m) => m.orgId)
      const orgs = await db.select().from(orgsTable).where(inArray(orgsTable.id, orgIds))
      return orgs.map((o) => ({
        id: o.id,
        name: o.name,
        domain: o.domain ?? null,
        metadata: o.metadata ?? null,
        createdAt: new Date(o.createdAt),
      }))
    },

    async listMembers(orgId, _ctx) {
      const rows = await db.select().from(orgMembersTable).where(eq(orgMembersTable.orgId, orgId))
      return rows.map((r) => ({
        orgId: r.orgId,
        identityId: r.identityId,
        roles: r.roles,
        invitedAt: r.invitedAt != null ? new Date(r.invitedAt) : null,
        joinedAt: new Date(r.joinedAt),
        leftAt: r.leftAt != null ? new Date(r.leftAt) : null,
      }))
    },

    async addMember(m, _ctx) {
      const now = Date.now()
      const joinedAt = new Date(now)
      await db.insert(orgMembersTable).values({
        orgId: m.orgId,
        identityId: m.identityId,
        roles: m.roles ?? [],
        invitedAt: m.invitedAt != null ? m.invitedAt.getTime() : null,
        joinedAt: now,
        leftAt: null,
      })
      return { ...m, invitedAt: m.invitedAt ?? null, joinedAt, leftAt: null }
    },

    async removeMember(orgId, identityId, _ctx) {
      await db
        .delete(orgMembersTable)
        .where(and(eq(orgMembersTable.orgId, orgId), eq(orgMembersTable.identityId, identityId)))
    },

    async setRoles(orgId, identityId, roles, _ctx) {
      await db
        .update(orgMembersTable)
        .set({ roles })
        .where(and(eq(orgMembersTable.orgId, orgId), eq(orgMembersTable.identityId, identityId)))
    },
  }
}

// ---------------------------------------------------------------------------
// 3. Wire everything into createAuth
// ---------------------------------------------------------------------------

const pool = new Pool()
const db = drizzle(pool)

const adapter = drizzlePgStorage(pool)

export const auth = createAuth({
  baseUrl: 'http://localhost:3000',
  transport: new AuthCookieTransport({ secure: false }),
  stores: {
    identities: adapter.identities,
    sessions: adapter.sessions,
    credentials: adapter.credentials,
    orgs: buildOrgStore(db),
    // orgs wired — duck-iam org scopes and auth org membership share the same org ID string
  },
  events: new InMemoryEvents(),
  limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
  // oauth: {},
  channels: {},
  mfa: {},
  identities: {},
  hijack: {},
  providers: [passwordProvider({ hasher: new ScryptHasher() })],
  plugins: [],
  strict: 'development',
  session: {},
  apiKeys: {},
  __tenantBrand: 'test',
})

const authAlt = new AuthEngine({
  baseUrl: 'http://localhost:3000',
  transport: new AuthCookieTransport({ secure: false }),
  stores: {
    identities: adapter.identities,
    sessions: adapter.sessions,
    credentials: adapter.credentials,
    orgs: buildOrgStore(db),
  },
  events: new InMemoryEvents(),
  limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
  mfa: {},
  identities: {},
  hijack: {},
  providers: [passwordProvider({ hasher: new Argon2idHasher() })],
  session: {},
  apiKeys: {},
  __tenantBrand: 'test',
})
