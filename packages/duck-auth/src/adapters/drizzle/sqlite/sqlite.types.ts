import type { authCredentials, authIdentities, authSessions } from './sqlite.schema'

/** Row types inferred from the SQLite schema, and the adapter's own options. */
export namespace Sqlite {
  export type IdentityRow = typeof authIdentities.$inferSelect
  /** What a store answers: the table minus the columns the projections in the adapter drop. */
  export type CredentialRow = typeof authCredentials.$inferSelect
  export type SessionRow = typeof authSessions.$inferSelect

  /** Structural shape of a better-sqlite3 `Database`, enough to detect it at runtime. */
  export type SqliteClientLike = {
    prepare: (sql: string) => unknown
    exec: (sql: string) => unknown
  }
}
