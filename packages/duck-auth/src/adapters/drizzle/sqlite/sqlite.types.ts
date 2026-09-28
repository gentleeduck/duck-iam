import type { authCredentials, authIdentities, authSessions } from './sqlite.schema'

/** Row types inferred from the SQLite schema, and the adapter's own options. */
export namespace Sqlite {
  /** An identity row. */
  export type IdentityRow = typeof authIdentities.$inferSelect
  /** A credential row. */
  export type CredentialRow = typeof authCredentials.$inferSelect
  /** A session row. */
  export type SessionRow = typeof authSessions.$inferSelect

  /** Structural shape of a better-sqlite3 `Database`, enough to detect it at runtime. */
  export type SqliteClientLike = {
    prepare: (sql: string) => unknown
    exec: (sql: string) => unknown
  }
}
