import type { SQL } from 'drizzle-orm'

/**
 * Stand-in for a drizzle `SQL` node; the fake dbs match plain condition objects, so it only needs to reach them.
 * NOTE: the one cast, and not a real `SQL`: an adapter that starts building real SQL fails loudly here.
 */
export function fakeSql<T extends object>(shape: T): T & SQL<unknown> {
  return shape as T & SQL<unknown>
}
