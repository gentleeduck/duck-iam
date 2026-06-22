import { sql } from 'drizzle-orm'
import {
  check,
  datetime,
  foreignKey,
  index,
  int,
  json,
  mysqlEnum,
  mysqlTable,
  primaryKey,
  unique,
  uniqueIndex,
  varchar,
} from 'drizzle-orm/mysql-core'
import type { AccessControl, IamPrimitives } from '../../../core/types'

/**
 * MySQL schema for the duck-iam IamDrizzle adapter.
 *
 * With the adapter's default `json: 'native'` mode, payload columns hold real
 * `json`; columns are typed with `$type<>()` for read-path safety. CHECK
 * constraints are enforced on MySQL 8.0.16+ and parsed-but-ignored below that.
 *
 * MySQL has no partial indexes and treats NULL as distinct in unique keys, so
 * global rows (NULL scope) are de-duplicated via a `COALESCE(scope, '')`
 * functional unique index - keeping uniqueness without changing the adapter's
 * `scope == null` = global semantics.
 *
 * No soft-delete columns; `created_by` / `updated_by` carry audit actors (left
 * NULL by the adapter - set via triggers or admin writes). See the Postgres
 * schema for fuller notes. Constraint naming: `pk_` `fk_` `uq_` `idx_` `ch_`.
 */

/** Allowed combining algorithms, kept in sync with {@link AccessControl.CombiningAlgorithm}. */
const IAM_COMBINE_ALGORITHMS = [
  'deny-overrides',
  'allow-overrides',
  'first-match',
  'highest-priority',
] as const satisfies readonly AccessControl.CombiningAlgorithm[]

/** Per-row current timestamp with millisecond precision. */
const nowMs = sql`CURRENT_TIMESTAMP(3)`

/** Stored ABAC policies. */
export const iamPolicies = mysqlTable(
  'access_policies',
  {
    id: varchar('id', { length: 191 }).notNull(),
    name: varchar('name', { length: 191 }).notNull(),
    description: varchar('description', { length: 1024 }),
    version: int('version').notNull().default(1),
    algorithm: mysqlEnum('algorithm', IAM_COMBINE_ALGORITHMS).notNull().default('deny-overrides'),
    rules: json('rules').$type<AccessControl.IRule[]>().notNull(),
    targets: json('targets').$type<NonNullable<AccessControl.IPolicy['targets']>>(),
    createdBy: varchar('created_by', { length: 191 }),
    updatedBy: varchar('updated_by', { length: 191 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
    updatedAt: datetime('updated_at', { fsp: 3 })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_access_policies', columns: [t.id] }),
    unique('uq_access_policies_name').on(t.name),
    check('ch_access_policies_name_not_blank', sql`length(trim(${t.name})) > 0`),
    check('ch_access_policies_version_positive', sql`${t.version} >= 1`),
  ],
)

/** Stored RBAC roles. `inherits` is a JSON array of parent role IDs. */
export const iamRoles = mysqlTable(
  'access_roles',
  {
    id: varchar('id', { length: 191 }).notNull(),
    name: varchar('name', { length: 191 }).notNull(),
    description: varchar('description', { length: 1024 }),
    permissions: json('permissions').$type<AccessControl.IPermission[]>().notNull(),
    inherits: json('inherits').$type<string[]>().notNull(),
    scope: varchar('scope', { length: 191 }),
    metadata: json('metadata').$type<IamPrimitives.Attributes>(),
    createdBy: varchar('created_by', { length: 191 }),
    updatedBy: varchar('updated_by', { length: 191 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
    updatedAt: datetime('updated_at', { fsp: 3 })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_access_roles', columns: [t.id] }),
    // COALESCE collapses NULL scopes so global roles are unique by name too.
    uniqueIndex('uq_access_roles_name_scope').on(t.name, sql`(coalesce(${t.scope}, ''))`),
    index('idx_access_roles_scope').on(t.scope),
    check('ch_access_roles_name_not_blank', sql`length(trim(${t.name})) > 0`),
  ],
)

/** Subject-to-role assignments. NULL scope is a global (unscoped) grant. */
export const iamAssignments = mysqlTable(
  'access_assignments',
  {
    id: varchar('id', { length: 191 }).$defaultFn(() => crypto.randomUUID()),
    subjectId: varchar('subject_id', { length: 191 }).notNull(),
    roleId: varchar('role_id', { length: 191 }).notNull(),
    scope: varchar('scope', { length: 191 }),
    createdBy: varchar('created_by', { length: 191 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
  },
  (t) => [
    primaryKey({ name: 'pk_access_assignments', columns: [t.id] }),
    foreignKey({
      name: 'fk_access_assignments_role',
      columns: [t.roleId],
      foreignColumns: [iamRoles.id],
    }).onDelete('cascade'),
    // COALESCE collapses NULL scopes so duplicate global grants conflict.
    uniqueIndex('uq_access_assignments_subject_role_scope').on(t.subjectId, t.roleId, sql`(coalesce(${t.scope}, ''))`),
    index('idx_access_assignments_subject').on(t.subjectId),
    index('idx_access_assignments_role').on(t.roleId),
    check('ch_access_assignments_subject_not_blank', sql`length(trim(${t.subjectId})) > 0`),
  ],
)

/** Per-subject attribute bags, one row per subject. */
export const iamSubjectAttrs = mysqlTable(
  'access_subject_attrs',
  {
    subjectId: varchar('subject_id', { length: 191 }).notNull(),
    data: json('data').$type<IamPrimitives.Attributes>().notNull(),
    updatedBy: varchar('updated_by', { length: 191 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
    updatedAt: datetime('updated_at', { fsp: 3 })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_access_subject_attrs', columns: [t.subjectId] }),
    check('ch_access_subject_attrs_subject_not_blank', sql`length(trim(${t.subjectId})) > 0`),
  ],
)
