import { sql } from 'drizzle-orm'
import {
  check,
  foreignKey,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
} from 'drizzle-orm/pg-core'
import type { IamAccessControl, IamPrimitives } from '../../../core/types'

/**
 * PostgreSQL schema for the duck-iam IamDrizzle adapter.
 *
 * Run `drizzle-kit generate` against this file to emit migrations.
 *
 * ### JSON storage
 * With the adapter's default `json: 'native'` mode, `rules`, `targets`,
 * `permissions`, `inherits`, `metadata`, and `data` hold real `jsonb` - so the
 * GIN indexes below work and payloads stay queryable. Columns are typed with
 * `$type<>()` for end-to-end safety. (Run the adapter in `json: 'string'` mode
 * only for text-column backends like SQLite.)
 *
 * ### Soft delete
 * No `deletedAt` columns: the adapter's `listRoles`/`listPolicies` do not
 * filter on deletion, so a soft-deleted role would keep granting access. Use
 * hard deletes (`deleteRole`/`deletePolicy`) to revoke.
 *
 * ### Audit
 * `created_by` / `updated_by` capture the actor behind a change. The adapter
 * has no actor context, so it leaves them NULL; set them from triggers or
 * direct admin writes.
 *
 * ### Constraint naming
 * pk_ primary key, fk_ foreign key, uq_ unique, idx_ index, ch_ check.
 * All declared in the table's (t) => [...] block.
 */

/**
 * Postgres enum mirroring {@link IamAccessControl.CombiningAlgorithm}. The
 * `satisfies` clause turns any drift between this list and the engine union
 * into a compile error.
 */
export const combineAlgorithm = pgEnum('access_combine_algorithm', [
  'deny-overrides',
  'allow-overrides',
  'first-match',
  'highest-priority',
] as const satisfies readonly IamAccessControl.CombiningAlgorithm[])

/**
 * Stored ABAC policies. `rules` and `targets` carry the policy payload as
 * `jsonb`; `algorithm` is constrained to the engine's combining algorithms.
 */
export const iamPolicies = pgTable(
  'access_policies',
  {
    id: text('id').notNull(),
    name: text('name').notNull(),
    description: text('description'),
    version: integer('version').notNull().default(1),
    algorithm: combineAlgorithm('algorithm').notNull().default('deny-overrides'),
    rules: jsonb('rules').$type<IamAccessControl.IRule[]>().notNull(),
    targets: jsonb('targets').$type<NonNullable<IamAccessControl.IPolicy['targets']>>(),
    createdBy: text('created_by'),
    updatedBy: text('updated_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_access_policies', columns: [t.id] }),
    unique('uq_access_policies_name').on(t.name),
    // Containment search over rules, e.g. `rules @> '[{"actions":["read"]}]'`.
    index('idx_access_policies_rules_gin').using('gin', t.rules),
    check('ch_access_policies_name_not_blank', sql`length(trim(${t.name})) > 0`),
    check('ch_access_policies_version_positive', sql`${t.version} >= 1`),
  ],
)

/**
 * Stored RBAC roles. `permissions` and `metadata` are `jsonb`; `inherits` is a
 * `jsonb` array of parent role IDs.
 */
export const iamRoles = pgTable(
  'access_roles',
  {
    id: text('id').notNull(),
    name: text('name').notNull(),
    description: text('description'),
    permissions: jsonb('permissions').$type<IamAccessControl.IPermission[]>().notNull(),
    inherits: jsonb('inherits').$type<string[]>().notNull().default(sql`'[]'::jsonb`),
    scope: text('scope'),
    metadata: jsonb('metadata').$type<IamPrimitives.Attributes>(),
    createdBy: text('created_by'),
    updatedBy: text('updated_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_access_roles', columns: [t.id] }),
    // Role name is unique per scope; NULL (global) scopes collapse so two
    // global roles cannot share a name.
    unique('uq_access_roles_name_scope').on(t.name, t.scope).nullsNotDistinct(),
    // Scoped roles only - global roles (NULL scope) are excluded to keep it small.
    index('idx_access_roles_scope').on(t.scope).where(sql`${t.scope} IS NOT NULL`),
    // Containment search over permissions, e.g. `permissions @> '[{"resource":"post"}]'`.
    index('idx_access_roles_permissions_gin').using('gin', t.permissions),
    check('ch_access_roles_name_not_blank', sql`length(trim(${t.name})) > 0`),
    check('ch_access_roles_scope_not_blank', sql`${t.scope} IS NULL OR length(trim(${t.scope})) > 0`),
  ],
)

/**
 * Subject-to-role assignments. A `NULL` scope is a global (unscoped)
 * assignment; a non-null scope binds the role to that tenant/scope. Unique on
 * `(subject_id, role_id, scope)` with NULL scopes collapsed, so `assignRole`'s
 * `onConflictDoNothing` is idempotent for global grants too.
 */
export const iamAssignments = pgTable(
  'access_assignments',
  {
    id: text('id').$defaultFn(() => crypto.randomUUID()),
    subjectId: text('subject_id').notNull(),
    roleId: text('role_id').notNull(),
    scope: text('scope'),
    createdBy: text('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ name: 'pk_access_assignments', columns: [t.id] }),
    foreignKey({
      name: 'fk_access_assignments_role',
      columns: [t.roleId],
      foreignColumns: [iamRoles.id],
    }).onDelete('cascade'),
    unique('uq_access_assignments_subject_role_scope').on(t.subjectId, t.roleId, t.scope).nullsNotDistinct(),
    index('idx_access_assignments_subject').on(t.subjectId),
    index('idx_access_assignments_role').on(t.roleId),
    // Scoped assignments only - speeds tenant-scoped lookups.
    index('idx_access_assignments_subject_scope').on(t.subjectId, t.scope).where(sql`${t.scope} IS NOT NULL`),
    check('ch_access_assignments_subject_not_blank', sql`length(trim(${t.subjectId})) > 0`),
    check('ch_access_assignments_scope_not_blank', sql`${t.scope} IS NULL OR length(trim(${t.scope})) > 0`),
  ],
)

/**
 * Per-subject attribute bags, one row per subject. `data` holds the
 * attribute map (`jsonb`) consumed by the ABAC condition engine.
 */
export const iamSubjectAttrs = pgTable(
  'access_subject_attrs',
  {
    subjectId: text('subject_id').notNull(),
    data: jsonb('data').$type<IamPrimitives.Attributes>().notNull(),
    updatedBy: text('updated_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_access_subject_attrs', columns: [t.subjectId] }),
    check('ch_access_subject_attrs_subject_not_blank', sql`length(trim(${t.subjectId})) > 0`),
  ],
)
