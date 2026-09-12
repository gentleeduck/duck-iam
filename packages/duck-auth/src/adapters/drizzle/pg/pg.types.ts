import type { NodePgDatabase, NodePgQueryResultHKT } from 'drizzle-orm/node-postgres'
import type { PgDatabase } from 'drizzle-orm/pg-core'
import type { authCredentials, authIdentities, authSessions } from './pg.schema'

export namespace Pg {
  export type IdentityRow = typeof authIdentities.$inferSelect
  export type CredentialRow = typeof authCredentials.$inferSelect
  export type SessionRow = typeof authSessions.$inferSelect

  export type NodePgPoolLike = {
    connect: () => Promise<unknown>
    query: (...args: unknown[]) => unknown
  }

  export type AnyNodePgDatabase = NodePgDatabase<Record<string, unknown>>

  /** What a statement runs on: the adapter's own handle, or the `tx` a transaction hands its callback. */
  export type Handle<TSchema extends Record<string, unknown> = Record<string, unknown>> = PgDatabase<
    NodePgQueryResultHKT,
    TSchema
  >
}
