import { sql } from 'drizzle-orm'
import { index, integer, jsonb, pgTable, text, timestamp, uniqueIndex } from 'drizzle-orm/pg-core'

/** PostgreSQL schema for the duck-iam Drizzle adapter; run `drizzle-kit generate` against this file. */

/**
 * Defines the Drizzle Postgres table for stored policies.
 *
 * JSON columns (`rules`, `targets`) carry the policy payload.
 */
export const accessPolicies = pgTable('access_policies', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  description: text('description'),
  version: integer('version').notNull().default(1),
  algorithm: text('algorithm').notNull().default('deny-overrides'),
  rules: jsonb('rules').notNull(),
  targets: jsonb('targets'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date()),
})

/**
 * Defines the Drizzle Postgres table for stored roles.
 *
 * `inherits` is a `text[]` column for fast lookups.
 */
export const accessRoles = pgTable('access_roles', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  description: text('description'),
  permissions: jsonb('permissions').notNull(),
  inherits: text('inherits').array().notNull().default(sql`ARRAY[]::text[]`),
  scope: text('scope'),
  metadata: jsonb('metadata'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date()),
})

/**
 * Defines the Drizzle Postgres table for subject-to-role assignments.
 *
 * Unique on `(subject_id, role_id, scope)`.
 */
export const accessAssignments = pgTable(
  'access_assignments',
  {
    id: text('id')
      .primaryKey()
      .$defaultFn(() => crypto.randomUUID()),
    subjectId: text('subject_id').notNull(),
    roleId: text('role_id')
      .notNull()
      .references(() => accessRoles.id, { onDelete: 'cascade' }),
    scope: text('scope'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('access_assignments_subject_role_scope_idx').on(t.subjectId, t.roleId, t.scope),
    index('access_assignments_subject_idx').on(t.subjectId),
  ],
)

/**
 * Defines the Drizzle Postgres table for per-subject attribute bags.
 *
 * One row per subject.
 */
export const accessSubjectAttrs = pgTable('access_subject_attrs', {
  subjectId: text('subject_id').primaryKey(),
  data: jsonb('data').notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date()),
})
