import { integer, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core'

// duck-auth's own pg tables, re-exported so `drizzle-kit generate` emits them from this one file —
// `users.id` below is a real FK into `authIdentities.id`, not a lookalike string.
export {
  authCredentials,
  authIdentities,
  authIdentityProviders,
  authSessions,
} from '@gentleduck/auth/adapters/drizzle/pg'
// combineAlgorithm must be re-exported alongside the tables, or drizzle-kit won't emit its
// `CREATE TYPE` — it only picks up enums that are top-level exports of this file.
export {
  combineAlgorithm,
  iamAssignments,
  iamPolicies,
  iamRoles,
  iamSubjectAttrs,
} from '@gentleduck/iam/adapters/drizzle/pg'

import { authIdentities } from '@gentleduck/auth/adapters/drizzle/pg'

export const companies = pgTable('companies', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

// `id` IS the duck-auth identity id — one signup creates one identity and one row here, never a
// separate join table. `email`/`name` are a denormalized copy of `authIdentities.profile`, kept in
// sync at write time, so the domain's own queries never need to join into `auth_identities`.
export const users = pgTable('users', {
  id: uuid('id')
    .primaryKey()
    .references(() => authIdentities.id),
  email: text('email').notNull().unique(),
  name: text('name').notNull(),
  companyId: text('company_id')
    .notNull()
    .references(() => companies.id),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
})

export const products = pgTable('products', {
  id: text('id').primaryKey(),
  companyId: text('company_id')
    .notNull()
    .references(() => companies.id),
  ownerId: uuid('owner_id')
    .notNull()
    .references(() => users.id),
  name: text('name').notNull(),
  priceCents: integer('price_cents').notNull(),
})

export const orders = pgTable('orders', {
  id: text('id').primaryKey(),
  companyId: text('company_id')
    .notNull()
    .references(() => companies.id),
  ownerId: uuid('owner_id')
    .notNull()
    .references(() => users.id),
  productId: text('product_id')
    .notNull()
    .references(() => products.id),
  quantity: integer('quantity').notNull(),
  status: text('status').notNull().default('pending'),
})

// `status` is a plain `text` column (no Postgres CHECK/enum), so nothing at the schema level stops
// a route from writing an arbitrary string. Route handlers validate with `isOrderStatus` instead.
export const ORDER_STATUSES = ['pending', 'shipped', 'delivered', 'cancelled'] as const
export type OrderStatus = (typeof ORDER_STATUSES)[number]
export function isOrderStatus(value: unknown): value is OrderStatus {
  return typeof value === 'string' && (ORDER_STATUSES as readonly string[]).includes(value)
}
