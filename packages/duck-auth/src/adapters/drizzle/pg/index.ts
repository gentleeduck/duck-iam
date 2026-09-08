/**
 * The element types of the JSON columns above, re-exported so a consumer can name them.
 *
 * `authIdentities.$inferSelect` mentions them, so anything that infers a type from the table -
 * a repository base class, a generic wrapper - has to be able to name them or TypeScript
 * refuses with TS2883 ("cannot be named without a reference to ... dist/index-<hash>.cjs").
 * Reachable through `@gentleduck/auth/adapters/sql` too; here as well because this is the
 * entrypoint the tables come from.
 */
export type { StoredFactor, StoredProviderLink } from '../../sql/stored-json'
export { createDrizzlePgBridge, drizzlePgStorage } from './pg'
export {
  authCredentials,
  authEvents,
  authIdentities,
  authSessions,
} from './pg.schema'
export type { Pg } from './pg.types'
