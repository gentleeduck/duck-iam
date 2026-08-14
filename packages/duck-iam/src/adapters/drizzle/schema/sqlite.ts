import { sql } from 'drizzle-orm'
import {
  check,
  foreignKey,
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
  unique,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core'
import { v7 as uuidv7 } from 'uuid'
import type { AccessControl } from '../../../core/types'

/**
 * SQLite schema for the duck-iam IamDrizzle adapter.
 *
 * SQLite has no native JSON or array type, so every payload column is TEXT and
 * the adapter must run in `json: 'string'` mode (`new IamDrizzleAdapter({ ...,
 * json: 'string' })`). Columns are typed with `$type<string>()` to reflect the
 * stored JSON text. `algorithm` is constrained via a CHECK.
 *
 * SQLite treats NULL as distinct in unique indexes, so global rows (NULL scope)
 * are de-duplicated via a `COALESCE(scope, '')` expression unique index.
 *
 * No soft-delete columns; `created_by` / `updated_by` carry audit actors (left
 * NULL by the adapter). See the Postgres schema for fuller notes. Constraint
 * naming: `pk_` `fk_` `uq_` `idx_` `ch_`.
 */

/** Allowed combining algorithms, kept in sync with {@link AccessControl.CombiningAlgorithm}. */
export const IAM_COMBINE_ALGORITHMS = [
  'deny-overrides',
  'allow-overrides',
  'first-match',
  'highest-priority',
] as const satisfies readonly AccessControl.CombiningAlgorithm[]

/** Per-row epoch-millisecond timestamp. */
const nowMs = sql`(unixepoch() * 1000)`

/** Stored ABAC policies. JSON payloads are TEXT and parsed by the adapter. */
export const iamPolicies = sqliteTable(
  'iam_policies',
  {
    id: text('id').notNull(),
    name: text('name').notNull(),
    description: text('description'),
    version: integer('version').notNull().default(1),
    algorithm: text('algorithm').$type<AccessControl.CombiningAlgorithm>().notNull().default('deny-overrides'),
    rules: text('rules').$type<string>().notNull(),
    targets: text('targets').$type<string>(),
    createdBy: text('created_by'),
    updatedBy: text('updated_by'),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(nowMs),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_iam_policies', columns: [t.id] }),
    unique('uq_iam_policies_name').on(t.name),
    check(
      'ch_iam_policies_algorithm_valid',
      sql`${t.algorithm} IN ('deny-overrides','allow-overrides','first-match','highest-priority')`,
    ),
    check('ch_iam_policies_name_not_blank', sql`length(trim(${t.name})) > 0`),
    check('ch_iam_policies_version_positive', sql`${t.version} >= 1`),
  ],
)

/** Stored RBAC roles. `inherits` is JSON TEXT defaulting to `'[]'`. */
export const iamRoles = sqliteTable(
  'iam_roles',
  {
    id: text('id').notNull(),
    name: text('name').notNull(),
    description: text('description'),
    permissions: text('permissions').$type<string>().notNull(),
    inherits: text('inherits').$type<string>().notNull().default('[]'),
    scope: text('scope'),
    metadata: text('metadata').$type<string>(),
    createdBy: text('created_by'),
    updatedBy: text('updated_by'),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(nowMs),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_iam_roles', columns: [t.id] }),
    // COALESCE collapses NULL scopes so global roles are unique by name too.
    uniqueIndex('uq_iam_roles_name_scope').on(t.name, sql`coalesce(${t.scope}, '')`),
    // Scoped roles only.
    index('idx_iam_roles_scope').on(t.scope).where(sql`${t.scope} IS NOT NULL`),
    check('ch_iam_roles_name_not_blank', sql`length(trim(${t.name})) > 0`),
  ],
)

/** Subject-to-role assignments. NULL scope is a global (unscoped) grant. */
export const iamAssignments = sqliteTable(
  'iam_assignments',
  {
    id: text('id')
      .notNull()
      .$defaultFn(() => uuidv7()),
    subjectId: text('subject_id').notNull(),
    roleId: text('role_id').notNull(),
    scope: text('scope'),
    createdBy: text('created_by'),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(nowMs),
  },
  (t) => [
    primaryKey({ name: 'pk_iam_assignments', columns: [t.id] }),
    foreignKey({
      name: 'fk_iam_assignments_role',
      columns: [t.roleId],
      foreignColumns: [iamRoles.id],
    }).onDelete('cascade'),
    // COALESCE collapses NULL scopes so duplicate global grants conflict.
    uniqueIndex('uq_iam_assignments_subject_role_scope').on(t.subjectId, t.roleId, sql`coalesce(${t.scope}, '')`),
    index('idx_iam_assignments_subject').on(t.subjectId),
    index('idx_iam_assignments_role').on(t.roleId),
    // Scoped assignments only.
    index('idx_iam_assignments_subject_scope').on(t.subjectId, t.scope).where(sql`${t.scope} IS NOT NULL`),
    check('ch_iam_assignments_subject_not_blank', sql`length(trim(${t.subjectId})) > 0`),
  ],
)

/** Per-subject attribute bags, one row per subject. JSON TEXT under `data`. */
export const iamSubjectAttrs = sqliteTable(
  'iam_subject_attrs',
  {
    subjectId: text('subject_id').notNull(),
    data: text('data').$type<string>().notNull(),
    updatedBy: text('updated_by'),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(nowMs),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_iam_subject_attrs', columns: [t.subjectId] }),
    check('ch_iam_subject_attrs_subject_not_blank', sql`length(trim(${t.subjectId})) > 0`),
  ],
)
