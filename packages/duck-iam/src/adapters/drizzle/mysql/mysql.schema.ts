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
import { v7 as uuidv7 } from 'uuid'
import type { AccessControl, IamPrimitives } from '../../../core/types'

/**
 * MySQL schema for the duck-iam IamDrizzle adapter. CHECK constraints are enforced on
 * MySQL 8.0.16+ and parsed-but-ignored below that. No partial indexes, so global rows
 * (NULL scope) are de-duplicated via a `COALESCE(scope, '')` functional unique index.
 * `created_by`/`updated_by` are left NULL by the adapter (no actor context); see the
 * Postgres schema for fuller notes.
 */

/** Mirrors {@link AccessControl.CombiningAlgorithm}. */
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
  'iam_policies',
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
    primaryKey({ name: 'pk_iam_policies', columns: [t.id] }),
    unique('uq_iam_policies_name').on(t.name),
    check('ch_iam_policies_name_not_blank', sql`${t.name} REGEXP '[^[:space:]]'`),
    check('ch_iam_policies_version_positive', sql`${t.version} >= 1`),
  ],
)

/** Stored RBAC roles. `inherits` is a JSON array of parent role IDs. */
export const iamRoles = mysqlTable(
  'iam_roles',
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
    primaryKey({ name: 'pk_iam_roles', columns: [t.id] }),
    uniqueIndex('uq_iam_roles_name_scope').on(t.name, sql`(coalesce(${t.scope}, ''))`),
    index('idx_iam_roles_scope').on(t.scope),
    check('ch_iam_roles_name_not_blank', sql`${t.name} REGEXP '[^[:space:]]'`),
  ],
)

/** Subject-to-role assignments. NULL scope is a global (unscoped) grant. */
export const iamAssignments = mysqlTable(
  'iam_assignments',
  {
    id: varchar('id', { length: 191 }).$defaultFn(() => uuidv7()),
    subjectId: varchar('subject_id', { length: 191 }).notNull(),
    roleId: varchar('role_id', { length: 191 }).notNull(),
    scope: varchar('scope', { length: 191 }),
    createdBy: varchar('created_by', { length: 191 }),
    updatedBy: varchar('updated_by', { length: 191 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
    updatedAt: datetime('updated_at', { fsp: 3 })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_iam_assignments', columns: [t.id] }),
    foreignKey({
      name: 'fk_iam_assignments_role',
      columns: [t.roleId],
      foreignColumns: [iamRoles.id],
    }).onDelete('cascade'),
    uniqueIndex('uq_iam_assignments_subject_role_scope').on(t.subjectId, t.roleId, sql`(coalesce(${t.scope}, ''))`),
    index('idx_iam_assignments_subject').on(t.subjectId),
    index('idx_iam_assignments_role').on(t.roleId),
    check('ch_iam_assignments_subject_not_blank', sql`${t.subjectId} REGEXP '[^[:space:]]'`),
  ],
)

/** Per-subject attribute bags, one row per subject. */
export const iamSubjectAttrs = mysqlTable(
  'iam_subject_attrs',
  {
    subjectId: varchar('subject_id', { length: 191 }).notNull(),
    data: json('data').$type<IamPrimitives.Attributes>().notNull(),
    createdBy: varchar('created_by', { length: 191 }),
    updatedBy: varchar('updated_by', { length: 191 }),
    createdAt: datetime('created_at', { fsp: 3 }).notNull().default(nowMs),
    updatedAt: datetime('updated_at', { fsp: 3 })
      .notNull()
      .default(nowMs)
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_iam_subject_attrs', columns: [t.subjectId] }),
    check('ch_iam_subject_attrs_subject_not_blank', sql`${t.subjectId} REGEXP '[^[:space:]]'`),
  ],
)
