import { createIam } from '@gentleduck/iam'
import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { and, eq, isNull, or } from 'drizzle-orm'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import type * as schema from './schema'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from './schema'

export type AppDb = NodePgDatabase<typeof schema>

// DuckMarket's authorization schema: a fixed action vocabulary granted action-by-action, roles
// that inherit upward, scoped per company. Scope stays `string` because company ids are dynamic
// rows, not a fixed literal union.
export const access = createIam({
  actions: ['read', 'create', 'update', 'delete', 'manageRoles'] as const,
  resources: ['companies', 'users', 'products', 'orders'] as const,
  roles: ['viewer', 'staff', 'manager', 'admin'] as const,
})

export type AppAction = (typeof access.actions)[number]
export type AppResource = (typeof access.resources)[number]
export type AppRole = (typeof access.roles)[number]
/** A company id. Dynamic, so it stays `string` rather than a literal union. */
export type AppScope = string

export const roleViewer = access
  .defineRole('viewer')
  .name('Viewer')
  .grant('read', 'companies')
  .grant('read', 'users')
  .grant('read', 'products')
  .grant('read', 'orders')
  .build()

export const roleStaff = access
  .defineRole('staff')
  .name('Staff')
  .inherits('viewer')
  .grant('create', 'products')
  .grant('update', 'products')
  .grant('create', 'orders')
  .build()

export const roleManager = access
  .defineRole('manager')
  .name('Manager')
  .inherits('staff')
  .grant('delete', 'products')
  .grant('update', 'orders')
  .grant('delete', 'orders')
  .grant('manageRoles', 'users')
  .build()

export const roleAdmin = access
  .defineRole('admin')
  .name('Admin')
  .inherits('manager')
  .grant('update', 'companies')
  .grant('delete', 'companies')
  .grant('update', 'users')
  .grant('delete', 'users')
  .build()

export const allRoles = [roleViewer, roleStaff, roleManager, roleAdmin]

// The engine's default `policyCombine: 'and'` requires every policy to independently allow, so
// this needs its own unconditional allow rule — a deny-only policy would reject every request,
// firing or not. `deny-overrides` then lets `deny-self-delete` win when both rules match.
export const denySelfAccountDeletePolicy = access
  .definePolicy('deny-self-account-delete')
  .name('Deny deleting your own user row')
  .algorithm('deny-overrides')
  .rule('allow-delete-others', (r) => r.allow().on('delete').of('users'))
  .rule('deny-self-delete', (r) =>
    r
      .deny()
      .on('delete')
      .of('users')
      .when((w) => w.isOwner('resource.attributes.id')),
  )
  .build()

export const allPolicies = [denySelfAccountDeletePolicy]

// Fail-closed subject id for an unauthenticated caller — a real subject with zero grants, never `null`.
export const ANONYMOUS_SUBJECT_ID = 'anonymous'

export function buildEngine(db: AppDb) {
  const adapter = new IamDrizzleAdapter<AppAction, AppResource, AppRole, AppScope, AppDb, 'pg'>({
    db,
    tables: { policies: iamPolicies, roles: iamRoles, assignments: iamAssignments, attrs: iamSubjectAttrs },
    ops: { and, eq, isNull, or },
  })

  return access.createEngine({ adapter, cacheTTL: 30 })
}

export type AppEngine = ReturnType<typeof access.createEngine>

export function isAppRole(value: unknown): value is AppRole {
  return typeof value === 'string' && (access.roles as readonly string[]).includes(value)
}

// Structural, not `AppEngine`, so a caller whose own DI type widens the role generic to `string`
// (NestJS's guard type does) can still pass its engine in without a cast.
interface RoleAdmin {
  admin: {
    assignRole(subjectId: string, roleId: string, scope: string): Promise<unknown>
    revokeRole(subjectId: string, roleId: string, scope: string): Promise<unknown>
  }
}

// assignRole is additive RBAC (a subject can hold several roles per scope); DuckMarket's model is
// "one role per company", so revoke the target's other roles in scope before assigning the new
// one. One shared function so all four frameworks enforce that the same way.
export async function setRole(
  engine: RoleAdmin,
  db: AppDb,
  targetId: string,
  roleId: AppRole,
  scope: AppScope,
): Promise<void> {
  const currentAssignments = await db
    .select({ roleId: iamAssignments.roleId })
    .from(iamAssignments)
    .where(and(eq(iamAssignments.subjectId, targetId), eq(iamAssignments.scope, scope)))
  for (const row of currentAssignments) {
    if (isAppRole(row.roleId) && row.roleId !== roleId) {
      await engine.admin.revokeRole(targetId, row.roleId, scope)
    }
  }
  await engine.admin.assignRole(targetId, roleId, scope)
}
