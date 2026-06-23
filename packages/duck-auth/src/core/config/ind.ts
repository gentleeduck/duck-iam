import { drizzle } from 'drizzle-orm/node-postgres'
import { integer, jsonb, pgTable, text } from 'drizzle-orm/pg-core'
import { and, eq, inArray } from 'drizzle-orm'
import { authDrizzlePgStorage } from '../../adapters/drizzle/pg'
import { AuthMemoryLimiter } from '../../limiters/memory'
import { AuthInMemoryEvents } from '../events'
import { AuthScryptHasher } from '../password/scrypt'
import { AuthCookieTransport } from '../transport'
import type { AuthOrg } from '../types/org'
import { createAuth } from './create-auth'
import { Pool } from 'pg'

// ---------------------------------------------------------------------------
// 1. Define org tables (add to your drizzle schema file)
// ---------------------------------------------------------------------------

interface OrgMeta {
  plan: 'free' | 'pro' | 'enterprise'
  avatarUrl?: string
}

const orgsTable = pgTable('orgs', {
  id:        text('id').primaryKey(),
  name:      text('name').notNull(),
  domain:    text('domain'),
  metadata:  jsonb('metadata').$type<OrgMeta>(),
  createdAt: integer('created_at').notNull(),
})

const orgMembersTable = pgTable('org_members', {
  orgId:       text('org_id').notNull().references(() => orgsTable.id, { onDelete: 'cascade' }),
  identityId:  text('identity_id').notNull(),
  roles:       text('roles').array().notNull().default([]),
  invitedAt:   integer('invited_at'),
  joinedAt:    integer('joined_at').notNull(),
  leftAt:      integer('left_at'),
})

// ---------------------------------------------------------------------------
// 2. Implement AuthOrg.IStore<OrgMeta> against those tables
// ---------------------------------------------------------------------------

function buildOrgStore(db: ReturnType<typeof drizzle>): AuthOrg.IStore<OrgMeta> {
  return {
    async getOrg(id, _ctx) {
      const rows = await db.select().from(orgsTable).where(eq(orgsTable.id, id)).limit(1)
      const row = rows[0]
      if (!row) return null
      return {
        id: row.id,
        name: row.name,
        domain: row.domain ?? undefined,
        metadata: row.metadata ?? undefined,
        createdAt: row.createdAt,
      }
    },

    async listOrgsForIdentity(identityId, _ctx) {
      const members = await db
        .select()
        .from(orgMembersTable)
        .where(and(eq(orgMembersTable.identityId, identityId)))
      if (!members.length) return []
      const orgIds = members.map((m) => m.orgId)
      const orgs = await db
        .select()
        .from(orgsTable)
        .where(inArray(orgsTable.id, orgIds))
      return orgs.map((o) => ({
        id: o.id,
        name: o.name,
        domain: o.domain ?? undefined,
        metadata: o.metadata ?? undefined,
        createdAt: o.createdAt,
      }))
    },

    async listMembers(orgId, _ctx) {
      const rows = await db
        .select()
        .from(orgMembersTable)
        .where(eq(orgMembersTable.orgId, orgId))
      return rows.map((r) => ({
        orgId: r.orgId,
        identityId: r.identityId,
        roles: r.roles,
        invitedAt: r.invitedAt ?? undefined,
        joinedAt: r.joinedAt,
        leftAt: r.leftAt ?? undefined,
      }))
    },

    async addMember(m, _ctx) {
      const now = Date.now()
      const row = { ...m, joinedAt: now }
      await db.insert(orgMembersTable).values({
        orgId: row.orgId,
        identityId: row.identityId,
        roles: row.roles ?? [],
        invitedAt: row.invitedAt ?? null,
        joinedAt: row.joinedAt,
        leftAt: null,
      })
      return row
    },

    async removeMember(orgId, identityId, _ctx) {
      await db
        .delete(orgMembersTable)
        .where(
          and(
            eq(orgMembersTable.orgId, orgId),
            eq(orgMembersTable.identityId, identityId),
          ),
        )
    },

    async setRoles(orgId, identityId, roles, _ctx) {
      await db
        .update(orgMembersTable)
        .set({ roles })
        .where(
          and(
            eq(orgMembersTable.orgId, orgId),
            eq(orgMembersTable.identityId, identityId),
          ),
        )
    },
  }
}

// ---------------------------------------------------------------------------
// 3. Wire everything into createAuth
// ---------------------------------------------------------------------------

const pool = new Pool()
const db = drizzle(pool)

export const auth = createAuth<{ email: string }, string, OrgMeta>({
  baseUrl: 'http://localhost:3000',
  transport: new AuthCookieTransport({ secure: false }),
  storage: {
    ...authDrizzlePgStorage<{ email: string }>(db),
    // orgs wired — duck-iam org scopes and auth org membership share the same org ID string
    orgs: buildOrgStore(db),
  },
  events: new AuthInMemoryEvents(),
  limiter: new AuthMemoryLimiter({ max: 5, windowMs: 60_000 }),
  passwords: { hasher: new AuthScryptHasher() },
})
