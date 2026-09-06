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
 * PostgreSQL schema for the duck-iam IamDrizzle adapter. Run `drizzle-kit generate`
 * against this file to emit migrations.
 *
 * `created_by` is written from `assignRole`'s `opts.actor` and `updated_by` from
 * `updateAssignmentScope`'s `actor`; both stay NULL when the caller names none,
 * and an external trigger may still set them. Every delete here is a hard delete -
 * `deletePolicy`/`deleteRole` so a name can be reused, `revokeRole` because a
 * revoked grant has no reason to be retained. No `deleted_at` column on any table.
 * Constraint naming: pk_ fk_ uq_ idx_ ch_.
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
    // No unique index on `name`. Nothing in the engine resolves a policy by name
    // - `id` is the key everywhere - so uniqueness here only bought a label
    // nobody reads, at the cost of making pg the one adapter where a second
    // policy with a duplicated name is impossible. Two adapters disagreeing
    // about whether a write succeeds is the failure this schema must not have.
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
    // Same as `iam_policies`: no unique index on (name, scope). Roles resolve by
    // `id`, and the other five adapters accept a duplicate name happily.
    index('idx_iam_roles_scope').on(t.scope).where(sql`${t.scope} IS NOT NULL`),
    // Containment search over permissions, e.g. `permissions @> '[{"resource":"post"}]'`.
    index('idx_iam_roles_permissions_gin').using('gin', t.permissions),
    check('ch_iam_roles_name_not_blank', sql`${t.name} ~ '[^[:space:]]'`),
    check('ch_iam_roles_scope_not_blank', sql`${t.scope} IS NULL OR ${t.scope} ~ '[^[:space:]]'`),
  ],
)

/**
 * `timestamptz` that survives Postgres's `infinity` and `-infinity`.
 *
 * Drizzle's own `timestamp()` maps every driver value through `new Date(...)`,
 * and `new Date('infinity')` is an Invalid Date - indistinguishable from a
 * genuinely corrupt column, which the adapter reads as "bound unreadable, row
 * inactive". So an assignment written `expires_at = 'infinity'`, the way
 * Postgres spells "never expires", read back as an expired grant: a wrong DENY
 * on the value an operator writes precisely to mean "always".
 *
 * Kept as `±Infinity` numbers, the adapter's `now < startsAt` / `now >=
 * expiresAt` comparisons give all four spellings the right answer without a
 * special case. The SQL type is unchanged, so this is not a migration.
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

/**
 * Subject-to-role assignments. NULL `scope` is a global (unscoped) grant. NULL
 * `starts_at`/`expires_at` means unbounded in that direction - a grant with both
 * NULL never expires, matching every assignment before this column existed.
 */
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
