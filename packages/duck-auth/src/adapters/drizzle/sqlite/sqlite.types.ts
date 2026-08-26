import type { BaseSQLiteDatabase } from 'drizzle-orm/sqlite-core'
import type { authCredentials, authEvents, authIdentities, authSessions } from './sqlite.schema'

/** Types for the drizzle sqlite adapter. */
export namespace Sqlite {
  export type IdentityRow = typeof authIdentities.$inferSelect
  export type CredentialRow = typeof authCredentials.$inferSelect
  export type SessionRow = typeof authSessions.$inferSelect
  export type EventRow = typeof authEvents.$inferSelect

  /** Structural shape of a better-sqlite3 `Database`, enough to detect it at runtime. */
  export type SqliteClientLike = {
    prepare: (sql: string) => unknown
    exec: (sql: string) => unknown
  }

  /** Driver-agnostic Drizzle sqlite db (better-sqlite3, libsql, bun:sqlite, ...). */
  export type AnySqliteDatabase = BaseSQLiteDatabase<'sync' | 'async', unknown, Record<string, unknown>>
}
