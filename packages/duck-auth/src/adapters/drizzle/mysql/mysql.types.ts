import type { authCredentials, authIdentities, authSessions } from './mysql.schema'

/** Row types inferred from the MySQL schema, and the adapter's own options. */
export namespace Mysql {
  /** What a store answers: the table minus the columns the projections in the adapter drop. */
  export type IdentityRow = Omit<typeof authIdentities.$inferSelect, 'emailNorm' | 'usernameNorm'>
  export type CredentialRow = Omit<typeof authCredentials.$inferSelect, 'passwordKey'>
  export type SessionRow = typeof authSessions.$inferSelect

  /** Structural shape of a mysql2 pool, enough to detect it at runtime. */
  export type MySql2PoolLike = {
    getConnection: (...args: unknown[]) => unknown
    query: (...args: unknown[]) => unknown
  }
}
