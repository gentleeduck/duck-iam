export { createDrizzleSqliteBridge, drizzleSqliteStorage } from './sqlite'
export {
  authCredentials,
  // Deprecated: use the auth-prefixed names above.
  authCredentials as credentialsTable,
  authEvents,
  authEvents as eventsTable,
  authIdentities,
  authIdentities as identitiesTable,
  authSessions,
  authSessions as sessionsTable,
} from './sqlite.schema'
export type { Sqlite } from './sqlite.types'
