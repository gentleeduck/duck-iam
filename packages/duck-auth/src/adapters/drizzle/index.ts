/** The JSON-column codecs, exported because the drizzle tables are a public export too: an app selecting
 *  from them directly needs the same parsers, not a hand-rolled `new Date(...)`. */

export { storedDate } from '~/core/predicates'
export {
  fromJsonColumn,
  isFactor,
  isProviderLink,
  parseActingAs,
  parseFactors,
  parseProviders,
} from './drizzle.stored-json'
