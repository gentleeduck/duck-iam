/**
 * Server-side IAM wiring: the Drizzle adapter over Postgres and the engine
 * built on it.
 *
 * The model itself - actions, resources, roles, policies, `CHECKS` - lives in
 * `./access-model`, which has no database import and is safe to load in the
 * browser. Everything there is re-exported from here, so existing imports of
 * `@/lib/access` are unaffected.
 */
import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { and, eq, isNull, or } from 'drizzle-orm'
import { type AppAction, type AppResource, access } from './access-model'
import { db } from './db'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from './db/schema'

export * from './access-model'

// ── Adapter ────────────────────────────────────────────────────────

// IamDrizzleAdapter.getSubjectRoles already filters to unscoped (scope IS NULL) only.
// IamDrizzleAdapter.getSubjectScopedRoles returns scoped assignments for scope-aware checks.
// Exported because the devtools admin routes read a subject's roles directly:
// `engine.admin` covers attributes and writes but has no role reader.
export const adapter = new IamDrizzleAdapter<AppAction, AppResource, string, string>({
  db,
  tables: {
    policies: iamPolicies,
    roles: iamRoles,
    assignments: iamAssignments,
    attrs: iamSubjectAttrs,
  },
  // `isNull` and `or` are optional to the adapter but it runs degraded without
  // them: an unscoped assignment cannot be matched in place, so moving a role
  // between scopes falls back to revoke + assign, and a bulk revoke issues one
  // DELETE per row. The devtools Subjects panel does both.
  ops: { eq, and, isNull, or },
})

// ── Engine ─────────────────────────────────────────────────────────

export const engine = access.createEngine({
  adapter,
  cacheTTL: 30,
})
