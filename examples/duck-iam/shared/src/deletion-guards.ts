import { eq } from 'drizzle-orm'
import type { AppDb } from './iam'
import { orders, products, users } from './schema'

// None of `users.companyId`/`products.ownerId`/`orders.ownerId` etc. declare `onDelete` in
// schema.ts, so Postgres defaults to `NO ACTION`: deleting a row that still has dependents throws
// an unhandled foreign-key-violation error rather than doing anything. That's deliberate — cascading
// would silently delete a member's `users` row out from under their still-live duck-auth identity,
// the mirror image of the orphan `signUp` already guards against — so the app must refuse the
// delete itself, with a clean response, before the database refuses it the hard way.

export async function companyHasUsers(db: AppDb, companyId: string): Promise<boolean> {
  const [row] = await db.select({ id: users.id }).from(users).where(eq(users.companyId, companyId)).limit(1)
  return !!row
}

export async function userOwnsRows(db: AppDb, userId: string): Promise<boolean> {
  const [product] = await db.select({ id: products.id }).from(products).where(eq(products.ownerId, userId)).limit(1)
  if (product) return true
  const [order] = await db.select({ id: orders.id }).from(orders).where(eq(orders.ownerId, userId)).limit(1)
  return !!order
}
