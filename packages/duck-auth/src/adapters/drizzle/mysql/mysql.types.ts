import type { MySql2Database } from 'drizzle-orm/mysql2'
import type { authCredentials, authEvents, authIdentities, authSessions } from './mysql.schema'

/**
 * @title Drizzle mysql types
 * @description Types for the drizzle mysql / MariaDB adapter.
 */
export namespace Mysql {
  export type IdentityRow = typeof authIdentities.$inferSelect
  export type CredentialRow = typeof authCredentials.$inferSelect
  export type SessionRow = typeof authSessions.$inferSelect
  export type EventRow = typeof authEvents.$inferSelect

  /** Structural shape of a mysql2 pool — enough to detect it at runtime. */
  export type MySql2PoolLike = {
    getConnection: (...args: unknown[]) => unknown
    query: (...args: unknown[]) => unknown
  }

  export type AnyMySql2Database = MySql2Database<Record<string, unknown>>
}
