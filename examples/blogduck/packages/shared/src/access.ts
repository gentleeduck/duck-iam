import { createIam, type IamAdapter } from '@gentleduck/iam'
import { type IamDrizzle, IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { and, eq } from 'drizzle-orm'
import { db, iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from './db'

// ── Config ──────────────────────────────────────────────────────

export const access = createIam({
  actions: ['create', 'read', 'update', 'delete'] as const,
  resources: ['post', 'user'] as const,
  scopes: ['org-1', 'org-2'] as const,
})

const _hi = access.defineRole('viewer')

export type AppAction = (typeof access.actions)[number]
export type AppResource = (typeof access.resources)[number]

// ── Roles ───────────────────────────────────────────────────────

export const viewer = access.defineRole('viewer').name('Viewer').grant('read', 'post').build()

export const editor = access
  .defineRole('editor')
  .name('Editor')
  .inherits('viewer')
  .grant('create', 'post')
  .grant('update', 'post')
  .build()

export const admin = access
  .defineRole('admin')
  .name('Admin')
  .inherits('editor')
  .grant('delete', 'post')
  .grant('create', 'user')
  .grant('read', 'user')
  .grant('update', 'user')
  .grant('delete', 'user')
  .build()

export const allRoles = [viewer, editor, admin]

// ── Adapter ─────────────────────────────────────────────────────

const adapter = new IamDrizzleAdapter({
  db,
  tables: {
    policies: iamPolicies,
    roles: iamRoles,
    assignments: iamAssignments,
    attrs: iamSubjectAttrs,
  },
  ops: { eq, and },
} as unknown as IamDrizzle.IConfig) as unknown as IamAdapter<AppAction, AppResource, string, never>

// ── Engine ──────────────────────────────────────────────────────

export const engine = access.createEngine({
  adapter,
  cacheTTL: 30,
})

// ── Permission checks for the frontend ──────────────────────────

export const CHECKS = access.checks([
  { action: 'create', resource: 'post' },
  { action: 'read', resource: 'post' },
  { action: 'update', resource: 'post' },
  { action: 'delete', resource: 'post' },
  { action: 'read', resource: 'user' },
  { action: 'delete', resource: 'user' },
])
