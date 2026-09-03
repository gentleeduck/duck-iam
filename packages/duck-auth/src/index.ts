// Runtime surface stays narrow - prefer subpath imports for anything not here.

/**
 * The domain types, re-exported so the root can name what the root can return.
 *
 * Exporting `AuthEngine` without them meant you could call a method but not
 * write down the type of what it handed back without a second import from
 * `@gentleduck/auth/core`. These are types only - they cost nothing at runtime
 * and the narrow runtime surface above is unchanged.
 */
export type {
  Anomaly,
  Batch,
  Bound,
  Compliance,
  Credential,
  DataAtRest,
  Engine,
  Envelope,
  Events,
  Flows,
  Hijack,
  Identities,
  Kms,
  M2m,
  Operations,
  Org,
  Pending,
  Provider,
  Sessions,
  TenantContext,
  Transport,
} from './core'
export { AuthEngine, authEngine } from './core/engine'
export { AuthError, rethrowAuthError, throwAuthError } from './core/errors'
export {
  BearerTransport as AuthBearerTransport,
  CompositeTransport as AuthCompositeTransport,
  CookieTransport as AuthCookieTransport,
} from './core/transport'
