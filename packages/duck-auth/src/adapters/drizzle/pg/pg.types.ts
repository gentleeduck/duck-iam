import type { authCredentials, authIdentities, authSessions } from './pg.schema'

/** Row types inferred from the Postgres schema, and the adapter's own options. */
export namespace Pg {
  export type IdentityRow = typeof authIdentities.$inferSelect
  /** What a store answers: the table minus the columns the projections in the adapter drop. */
  export type CredentialRow = typeof authCredentials.$inferSelect
  export type SessionRow = typeof authSessions.$inferSelect

  export type NodePgPoolLike = {
    connect: () => Promise<unknown>
    query: (...args: unknown[]) => unknown
  }
}
