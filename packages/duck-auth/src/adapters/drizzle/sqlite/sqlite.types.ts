import type { BaseSQLiteDatabase } from 'drizzle-orm/sqlite-core'
import type { credentialsTable, eventsTable, identitiesTable, sessionsTable } from './sqlite.schema'

/**
 * @title Drizzle sqlite types
 * @description Types for the drizzle sqlite adapter.
 */
export namespace Sqlite {
  export type IdentityRow = typeof identitiesTable.$inferSelect
  export type CredentialRow = typeof credentialsTable.$inferSelect
  export type SessionRow = typeof sessionsTable.$inferSelect
  export type EventRow = typeof eventsTable.$inferSelect

  /** Structural shape of a better-sqlite3 `Database` — enough to detect it at runtime. */
  export type SqliteClientLike = {
    prepare: (sql: string) => unknown
    exec: (sql: string) => unknown
  }

  /** Driver-agnostic Drizzle sqlite db (better-sqlite3, libsql, bun:sqlite, ...). */
  export type AnySqliteDatabase = BaseSQLiteDatabase<'sync' | 'async', unknown, Record<string, unknown>>
}
