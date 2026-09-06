// Barrel. The JSON Schema itself and the recursive condition-group builders
// live in `schema.ts`, so this file stays a re-export list like every other
// `core/*` barrel - `index.ts` says what a module publishes, never what it
// does.
export { POLICY_JSON_SCHEMA } from './schema'
