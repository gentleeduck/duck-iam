// The runtime surface stays narrow; anything not here is a subpath import.

/**
 * The domain types, re-exported so the root can name what the root returns. Without them a caller
 * can invoke a method but cannot write down the type of what it hands back without a second import
 * from `@gentleduck/auth/core`. Types only: they cost nothing at runtime.
 */
export type {
  Actor,
  Anomaly,
  Answer,
  Bound,
  Compliance,
  Credential,
  DataAtRest,
  Deliver,
  DeliveryKind,
  Engine,
  Envelope,
  Events,
  Flows,
  Hijack,
  Identities,
  Kms,
  M2m,
  Org,
  Pending,
  Provider,
  Sessions,
  TenantContext,
  Transport,
} from './core'
export { actorId, currentActor, resolveActor, setDefaultActorResolver, withActor } from './core/actor'
export { ABSENT, answer, orNull } from './core/answer'
export { AuthEngine, authEngine } from './core/engine'
export { AuthError, rethrowAuthError, throwAuthError } from './core/errors'
export {
  BearerTransport as AuthBearerTransport,
  CompositeTransport as AuthCompositeTransport,
  CookieTransport as AuthCookieTransport,
} from './core/transport'
