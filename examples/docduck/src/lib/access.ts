import { createIam } from '@gentleduck/iam'
import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { and, eq } from 'drizzle-orm'
import { db } from './db'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from './db/schema'

// ── Typed context for ABAC policies ────────────────────────────────

interface DocDuckContext {
  subject: {
    id: string
    attributes: { workspaceRole: string }
  }
  resource: {
    type: string
    id?: string
    attributes: { ownerId: string; isPublic: boolean }
  }
  environment: Record<string, never>
}

// ── Config ─────────────────────────────────────────────────────────

export const access = createIam({
  actions: ['create', 'read', 'update', 'delete', 'share', 'manage'] as const,
  resources: ['document', 'workspace', 'member'] as const,
  context: {} as unknown as DocDuckContext,
})

export type AppAction = (typeof access.actions)[number]
export type AppResource = (typeof access.resources)[number]

// ── Roles (workspace-scoped via assignments) ───────────────────────

export const viewer = access
  .defineRole('viewer')
  .name('Viewer')
  .grant('read', 'document')
  .grant('read', 'workspace')
  .grant('read', 'member')
  .build()

export const editor = access
  .defineRole('editor')
  .name('Editor')
  .inherits('viewer')
  .grant('create', 'document')
  .grant('update', 'document')
  .build()

export const admin = access
  .defineRole('admin')
  .name('Admin')
  .inherits('editor')
  .grant('delete', 'document')
  .grant('share', 'document')
  .grant('manage', 'member')
  .grant('update', 'workspace')
  .build()

export const owner = access.defineRole('owner').name('Owner').inherits('admin').grant('delete', 'workspace').build()

export const allRoles = [viewer, editor, admin, owner]

// ── ABAC Policies ──────────────────────────────────────────────────

export const docOwnershipPolicy = access
  .definePolicy('doc-ownership')
  .name('Document Ownership')
  .desc('Editors can only update/delete their own documents; admins/owners bypass')
  .target({ actions: ['update', 'delete'], resources: ['document'] })
  .algorithm('deny-overrides')
  .rule('deny-non-owner-edit', (r) =>
    r
      .deny()
      .on('update', 'delete')
      .of('document')
      .when((w) => w.in('subject.attributes.workspaceRole', ['editor']).resourceAttr('ownerId', 'neq', '$subject.id')),
  )
  .build()

export const publicDocsPolicy = access
  .definePolicy('public-docs')
  .name('Public Documents')
  .desc('Public documents are readable by any workspace member')
  .target({ actions: ['read'], resources: ['document'] })
  .algorithm('allow-overrides')
  .rule('allow-public-read', (r) =>
    r
      .allow()
      .on('read')
      .of('document')
      .when((w) => w.resourceAttr('isPublic', 'eq', true)),
  )
  .build()

// NOTE: ABAC policies are defined but NOT seeded to the DB.
// The engine AND-combines all policies, and when a policy's targets
// don't match a request, it defaults to deny. This means any policy
// stored in the DB will deny requests outside its target scope.
// For this example, RBAC roles provide all needed permissions.
// To use ABAC policies, ensure every policy covers all action/resource
// combinations (or fix the target-mismatch behavior upstream).
export const allPolicies: (typeof docOwnershipPolicy)[] = []

// ── Adapter ────────────────────────────────────────────────────────

// IamDrizzleAdapter.getSubjectRoles already filters to unscoped (scope IS NULL) only.
// IamDrizzleAdapter.getSubjectScopedRoles returns scoped assignments for scope-aware checks.
const adapter = new IamDrizzleAdapter<AppAction, AppResource, string, string>({
  db,
  tables: {
    policies: iamPolicies,
    roles: iamRoles,
    assignments: iamAssignments,
    attrs: iamSubjectAttrs,
  },
  ops: { eq, and },
})

// ── Engine ─────────────────────────────────────────────────────────

export const engine = access.createEngine({
  adapter,
  cacheTTL: 30,
})

// ── Permission checks for the frontend ─────────────────────────────

export const CHECKS = access.checks([
  { action: 'create', resource: 'document' },
  { action: 'read', resource: 'document' },
  { action: 'update', resource: 'document' },
  { action: 'delete', resource: 'document' },
  { action: 'share', resource: 'document' },
  { action: 'read', resource: 'workspace' },
  { action: 'update', resource: 'workspace' },
  { action: 'delete', resource: 'workspace' },
  { action: 'manage', resource: 'member' },
  { action: 'read', resource: 'member' },
])
