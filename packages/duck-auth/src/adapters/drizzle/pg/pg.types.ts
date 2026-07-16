import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import type { credentialsTable, eventsTable, identitiesTable, sessionsTable } from './pg.schema'

/**
 * @title Drizzle pg types
 * @description Types for the drizzle pg adapter.
 */
export namespace Pg {
  export type IdentityRow = typeof identitiesTable.$inferSelect
  export type CredentialRow = typeof credentialsTable.$inferSelect
  export type SessionRow = typeof sessionsTable.$inferSelect
  export type EventRow = typeof eventsTable.$inferSelect

  export type NodePgPoolLike = {
    connect: () => Promise<unknown>
    query: (...args: unknown[]) => unknown
  }

  export type AnyNodePgDatabase = NodePgDatabase<Record<string, unknown>>
}
