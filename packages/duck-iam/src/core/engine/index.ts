export { IamEngine, iamEngine, iamFlushSharedCaches } from './engine'
export type { Bound } from './engine.bound'
/**
 * The engine's scope relations: `iamScopeAncestors` walks a scope up; `iamScopeCovers` checks a grant's reach.
 * NOTE: `iam`-prefixed because the package root is one flat `export *` namespace.
 */
export { scopeAncestors as iamScopeAncestors, scopeCovers as iamScopeCovers } from './engine.libs'
export type { IamEngineTypes } from './engine.types'
