import { sql } from 'drizzle-orm'
import {
  check,
  customType,
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
import { v7 as uuidv7 } from 'uuid'
import type { AccessControl, IamPrimitives } from '../../../core/types'

/**
 * PostgreSQL schema for the drizzle adapter; run `drizzle-kit generate` against it to emit migrations.
 * `created_by`/`updated_by` come from the caller's actor (NULL when none). Deletes are hard deletes.
 * Constraint prefixes: pk_ fk_ uq_ idx_ ch_.
 */

/** Mirrors {@link AccessControl.CombiningAlgorithm}; `satisfies` catches drift at compile time. */
export const combineAlgorithm = pgEnum('iam_combine_algorithm', [
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
    // NOTE: no unique index on `name`: policies resolve by `id`, and every adapter must accept a duplicate name.
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
    // NOTE: no unique index on (name, scope), for the same reason as `iam_policies`.
    index('idx_iam_roles_scope').on(t.scope).where(sql`${t.scope} IS NOT NULL`),
    // Containment search over permissions, e.g. `permissions @> '[{"resource":"post"}]'`.
    index('idx_iam_roles_permissions_gin').using('gin', t.permissions),
    check('ch_iam_roles_name_not_blank', sql`${t.name} ~ '[^[:space:]]'`),
    check('ch_iam_roles_scope_not_blank', sql`${t.scope} IS NULL OR ${t.scope} ~ '[^[:space:]]'`),
  ],
)

/**
 * `timestamptz` that maps Postgres `infinity`/`-infinity` to `Infinity`/`-Infinity`; same SQL type, so no migration.
 * INFO: drizzle's `timestamp()` yields `new Date('infinity')`, an Invalid Date the adapter reads as an inactive bound.
 */
const timestamptzWithInfinity = customType<{
  data: Date | number
  driverData: string
}>({
  dataType() {
    return 'timestamp with time zone'
  },
  fromDriver(value: string): Date | number {
    if (value === 'infinity') return Number.POSITIVE_INFINITY
    if (value === '-infinity') return Number.NEGATIVE_INFINITY
    return new Date(value)
  },
  toDriver(value: Date | number): string {
    if (value === Number.POSITIVE_INFINITY) return 'infinity'
    if (value === Number.NEGATIVE_INFINITY) return '-infinity'
    if (value instanceof Date) return value.toISOString()
    return new Date(value).toISOString()
  },
})

/** Subject-to-role assignments. NULL `scope` is a global grant; NULL `starts_at`/`expires_at` is unbounded that way. */
export const iamAssignments = pgTable(
  'iam_assignments',
  {
    id: text('id')
      .notNull()
      .$defaultFn(() => uuidv7()),
    subjectId: text('subject_id').notNull(),
    roleId: text('role_id').notNull(),
    scope: text('scope'),
    startsAt: timestamptzWithInfinity('starts_at'),
    expiresAt: timestamptzWithInfinity('expires_at'),
    attributes: jsonb('attributes').$type<IamPrimitives.Attributes>(),
    createdBy: text('created_by'),
    updatedBy: text('updated_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
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
    index('idx_iam_assignments_expires_at').on(t.expiresAt).where(sql`${t.expiresAt} IS NOT NULL`),
    check('ch_iam_assignments_subject_not_blank', sql`${t.subjectId} ~ '[^[:space:]]'`),
    check('ch_iam_assignments_scope_not_blank', sql`${t.scope} IS NULL OR ${t.scope} ~ '[^[:space:]]'`),
    check(
      'ch_iam_assignments_starts_before_expires',
      sql`${t.startsAt} IS NULL OR ${t.expiresAt} IS NULL OR ${t.startsAt} < ${t.expiresAt}`,
    ),
  ],
)

/** Per-subject attribute bags, one row per subject. `data` is `jsonb`. */
export const iamSubjectAttrs = pgTable(
  'iam_subject_attrs',
  {
    subjectId: text('subject_id').notNull(),
    data: jsonb('data').$type<IamPrimitives.Attributes>().notNull(),
    createdBy: text('created_by'),
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
