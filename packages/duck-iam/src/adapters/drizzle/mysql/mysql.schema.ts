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
  uniqueIndex,
  varchar,
} from 'drizzle-orm/mysql-core'
import { v7 as uuidv7 } from 'uuid'
import type { AccessControl, IamPrimitives } from '../../../core/types'

/**
 * MySQL schema for the duck-iam IamDrizzle adapter. CHECK constraints are enforced on
 * MySQL 8.0.16+ and parsed-but-ignored below that. No partial indexes, so global rows
 * (NULL scope) are de-duplicated via a `COALESCE(scope, '')` functional unique index.
 * `created_by`/`updated_by` are written from the actor the caller supplies and stay
 * NULL when none is named; see the Postgres schema for fuller notes.
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
    // No unique index on `name`. Nothing in the engine resolves a policy by name
    // - `id` is the key everywhere - so uniqueness here only bought a label
    // nobody reads, at the cost of making pg the one adapter where a second
    // policy with a duplicated name is impossible. Two adapters disagreeing
    // about whether a write succeeds is the failure this schema must not have.
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
    // Expression default, the only form MySQL accepts for a JSON column
    // (8.0.13+). Without it `inherits` was the one column an insert had to
    // supply here and nowhere else.
    inherits: json('inherits').$type<string[]>().notNull().default(sql`('[]')`),
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
    // Same as `iam_policies`: no unique index on (name, scope). Roles resolve by
    // `id`, and the other five adapters accept a duplicate name happily.
    index('idx_iam_roles_scope').on(t.scope),
    check('ch_iam_roles_name_not_blank', sql`${t.name} REGEXP '[^[:space:]]'`),
    check('ch_iam_roles_scope_not_blank', sql`${t.scope} IS NULL OR ${t.scope} REGEXP '[^[:space:]]'`),
  ],
)

/**
 * Subject-to-role assignments. NULL scope is a global (unscoped) grant. NULL
 * `starts_at`/`expires_at` means unbounded in that direction - a grant with both
 * NULL never expires, matching every assignment before this column existed.
 */
export const iamAssignments = mysqlTable(
  'iam_assignments',
  {
    id: varchar('id', { length: 191 })
      .notNull()
      .$defaultFn(() => uuidv7()),
    subjectId: varchar('subject_id', { length: 191 }).notNull(),
    roleId: varchar('role_id', { length: 191 }).notNull(),
    scope: varchar('scope', { length: 191 }),
    startsAt: datetime('starts_at', { fsp: 3 }),
    expiresAt: datetime('expires_at', { fsp: 3 }),
    attributes: json('attributes').$type<IamPrimitives.Attributes>(),
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
    // Unfiltered where Postgres and SQLite use `WHERE scope IS NOT NULL`:
    // MySQL has no partial indexes, and the scoped-subject lookup still needs
    // the composite rather than a subject scan plus a filter.
    index('idx_iam_assignments_subject_scope').on(t.subjectId, t.scope),
    index('idx_iam_assignments_expires_at').on(t.expiresAt),
    check('ch_iam_assignments_subject_not_blank', sql`${t.subjectId} REGEXP '[^[:space:]]'`),
    check('ch_iam_assignments_scope_not_blank', sql`${t.scope} IS NULL OR ${t.scope} REGEXP '[^[:space:]]'`),
    check(
      'ch_iam_assignments_starts_before_expires',
      sql`${t.startsAt} IS NULL OR ${t.expiresAt} IS NULL OR ${t.startsAt} < ${t.expiresAt}`,
    ),
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
