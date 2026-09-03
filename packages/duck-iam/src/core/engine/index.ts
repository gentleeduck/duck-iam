export { IamEngine, iamEngine, iamFlushSharedCaches } from './engine'
export type { Bound } from './engine.bound'
/**
 * The engine's own scope walk, exported so callers doing scope-aware rank or
 * reach calculations of their own use the same relation the engine matches
 * with instead of reimplementing it and drifting.
 *
 * `iam`-prefixed on the way out, like the `core/conditions` barrel does: the
 * package root is one flat namespace assembled from `export *`, so an
 * unprefixed name there is one a consumer's own code can collide with.
 * `iamScopeAncestors` walks a request scope up to its ancestors;
 * `iamScopeCovers` answers the other direction - whether a grant declared at
 * one scope reaches a request made at another.
 */
export { scopeAncestors as iamScopeAncestors, scopeCovers as iamScopeCovers } from './engine.libs'
export type { IamEngineTypes } from './engine.types'
