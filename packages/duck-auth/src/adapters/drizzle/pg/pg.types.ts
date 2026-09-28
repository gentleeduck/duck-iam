import type { authCredentials, authIdentities, authSessions } from './pg.schema'

/** Row types inferred from the Postgres schema, and the adapter's own options. */
export namespace Pg {
  /** An identity row. */
  export type IdentityRow = typeof authIdentities.$inferSelect
  /** A credential row. */
  export type CredentialRow = typeof authCredentials.$inferSelect
  /** A session row. */
  export type SessionRow = typeof authSessions.$inferSelect

  /** Structural shape of a node-postgres pool, enough to detect it at runtime. */
  export type NodePgPoolLike = {
    connect: () => Promise<unknown>
    query: (...args: never[]) => unknown
  }
}
