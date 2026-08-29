export { createDrizzleMysqlBridge, drizzleMysqlStorage } from './mysql'
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
} from './mysql.schema'
export type { Mysql } from './mysql.types'
