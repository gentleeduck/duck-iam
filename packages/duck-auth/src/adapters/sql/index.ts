export {
  assertEmailFree,
  assertProviderSubFree,
  assertRestorable,
  claimedProviderSubs,
  createSqlStores,
  isRestorable,
  pickFreshestCredential,
  profileEmail,
  providerSubKey,
} from './sql'
export type { SqlBridge } from './sql.types'
export type { StoredFactor, StoredProviderLink } from './stored-json'
/**
 * The JSON-column codecs. Exported because the drizzle tables are a public
 * export too: an app that selects from `authIdentities`/`authSessions` directly,
 * or writes its own bridge over another driver, needs the same parsers the
 * adapters use rather than a hand-rolled `new Date(...)` that turns unreadable
 * input into an `Invalid Date`.
 */
export {
  fromJsonColumn,
  isFactor,
  isProviderLink,
  parseActingAs,
  parseFactors,
  parseProviders,
  reviveIdentityRow,
  reviveIdentityRowOrNull,
  reviveSessionRow,
  reviveSessionRowRequired,
  storedDate,
} from './stored-json'
