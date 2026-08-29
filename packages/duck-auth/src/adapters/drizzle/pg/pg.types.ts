import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import type { authCredentials, authEvents, authIdentities, authSessions } from './pg.schema'

/** Types for the drizzle pg adapter. */
export namespace Pg {
  export type IdentityRow = typeof authIdentities.$inferSelect
  export type CredentialRow = typeof authCredentials.$inferSelect
  export type SessionRow = typeof authSessions.$inferSelect
  export type EventRow = typeof authEvents.$inferSelect

  export type NodePgPoolLike = {
    connect: () => Promise<unknown>
    query: (...args: unknown[]) => unknown
  }

  export type AnyNodePgDatabase = NodePgDatabase<Record<string, unknown>>
}
