import type { SQL } from 'drizzle-orm'

/**
 * A stand-in for a drizzle `SQL` node.
 *
 * `ops.eq`, `ops.and`, `ops.isNull` and `ops.or` are declared with drizzle's
 * own types, so they return a real `SQL` - a dozen members of query-building
 * machinery none of these tests use. The fake `db` in each of these files
 * matches rows against a plain condition object instead, so what the adapter
 * needs from an operator result is only that it reaches that `db` unchanged.
 *
 * This is the one cast, gathered in one place rather than repeated at every
 * operator in every mock. The value is deliberately **not** an `SQL`: calling
 * any `SQL` method on it fails loudly, which is the correct outcome, because
 * an adapter that started building real SQL would no longer be talking to
 * these fakes at all.
 */
export function fakeSql<T extends object>(shape: T): T & SQL<unknown> {
  return shape as T & SQL<unknown>
}
