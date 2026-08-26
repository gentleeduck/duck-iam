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
  uuid,
} from 'drizzle-orm/pg-core'
import { v7 as uuidv7 } from 'uuid'
import type { AccessControl, IamPrimitives } from '../../../core/types'

/**
 * PostgreSQL schema for the duck-iam IamDrizzle adapter. Run `drizzle-kit generate`
 * against this file to emit migrations.
 *
 * No `deletedAt` columns: `listRoles`/`listPolicies` don't filter on deletion, so a
 * soft-deleted role would keep granting access. `created_by`/`updated_by` are left
 * NULL by the adapter (no actor context); set them from triggers or admin writes.
 * Constraint naming: pk_ fk_ uq_ idx_ ch_.
 */

/** Mirrors {@link AccessControl.CombiningAlgorithm}; `satisfies` catches drift at compile time. */
export const combineAlgorithm = pgEnum('access_combine_algorithm', [
  'deny-overrides',
  'allow-overrides',
  'first-match',
  'highest-priority',
] as const satisfies readonly AccessControl.CombiningAlgorithm[])

/** Stored ABAC policies. `rules`/`targets` are `jsonb`. */
export const iamPolicies = pgTable(
  'iam_policies',
  {
    id: text('id').notNull(),
    name: text('name').notNull(),
    description: text('description'),
    version: integer('version').notNull().default(1),
    algorithm: combineAlgorithm('algorithm').notNull().default('deny-overrides'),
    rules: jsonb('rules').$type<AccessControl.IRule[]>().notNull(),
    targets: jsonb('targets').$type<NonNullable<AccessControl.IPolicy['targets']>>(),
    createdBy: text('created_by'),
    updatedBy: text('updated_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    primaryKey({ name: 'pk_iam_policies', columns: [t.id] }),
    unique('uq_iam_policies_name').on(t.name),
    // Containment search over rules, e.g. `rules @> '[{"actions":["read"]}]'`.
    index('idx_iam_policies_rules_gin').using('gin', t.rules),
    check('ch_iam_policies_name_not_blank', sql`${t.name} ~ '[^[:space:]]'`),
    check('ch_iam_policies_version_positive', sql`${t.version} >= 1`),
  ],
)

/** Stored RBAC roles. `permissions`/`metadata`/`inherits` are `jsonb`. */
export const iamRoles = pgTable(
  'iam_roles',
  {
    id: text('id').notNull(),
    name: text('name').notNull(),
    description: text('description'),
    permissions: jsonb('permissions').$type<AccessControl.IPermission[]>().notNull(),
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
    primaryKey({ name: 'pk_iam_roles', columns: [t.id] }),
    unique('uq_iam_roles_name_scope').on(t.name, t.scope).nullsNotDistinct(),
    index('idx_iam_roles_scope').on(t.scope).where(sql`${t.scope} IS NOT NULL`),
    // Containment search over permissions, e.g. `permissions @> '[{"resource":"post"}]'`.
    index('idx_iam_roles_permissions_gin').using('gin', t.permissions),
    check('ch_iam_roles_name_not_blank', sql`${t.name} ~ '[^[:space:]]'`),
    check('ch_iam_roles_scope_not_blank', sql`${t.scope} IS NULL OR ${t.scope} ~ '[^[:space:]]'`),
  ],
)

/** Subject-to-role assignments. NULL `scope` is a global (unscoped) grant. */
export const iamAssignments = pgTable(
  'iam_assignments',
  {
    id: uuid('id')
      .notNull()
      .$defaultFn(() => uuidv7()),
    subjectId: text('subject_id').notNull(),
    roleId: text('role_id').notNull(),
    scope: text('scope'),
    createdBy: text('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ name: 'pk_iam_assignments', columns: [t.id] }),
    foreignKey({
      name: 'fk_iam_assignments_role',
      columns: [t.roleId],
      foreignColumns: [iamRoles.id],
    }).onDelete('cascade'),
    unique('uq_iam_assignments_subject_role_scope').on(t.subjectId, t.roleId, t.scope).nullsNotDistinct(),
    index('idx_iam_assignments_subject').on(t.subjectId),
    index('idx_iam_assignments_role').on(t.roleId),
    index('idx_iam_assignments_subject_scope').on(t.subjectId, t.scope).where(sql`${t.scope} IS NOT NULL`),
    check('ch_iam_assignments_subject_not_blank', sql`${t.subjectId} ~ '[^[:space:]]'`),
    check('ch_iam_assignments_scope_not_blank', sql`${t.scope} IS NULL OR ${t.scope} ~ '[^[:space:]]'`),
  ],
)

/** Per-subject attribute bags, one row per subject. `data` is `jsonb`. */
export const iamSubjectAttrs = pgTable(
  'iam_subject_attrs',
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
    primaryKey({ name: 'pk_iam_subject_attrs', columns: [t.subjectId] }),
    check('ch_iam_subject_attrs_subject_not_blank', sql`${t.subjectId} ~ '[^[:space:]]'`),
  ],
)
