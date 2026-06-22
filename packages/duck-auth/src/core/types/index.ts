/**
 * Public type-only barrel. All shapes are exposed via namespaces
 * (`AuthIdentity.IIdentity`, `AuthSession.ISession`, ...) so consumers get
 * stable, semantically-grouped imports.
 */

export type { AuthAnomaly } from './anomaly'
export type { AuthChannel } from './channel'
export type { AuthTenantContext } from './context'
export type { AuthCredential } from './credential'
export type { AuthDataAtRest } from './dataAtRest'
export type { AuthError } from './error'
export type { AuthEvents } from './events'
export type { AuthHasher } from './hasher'
export type { AuthIdempotency } from './idempotency'
export type { AuthIdentity } from './identity'
export type { AuthKms } from './kms'
export type { AuthLimiter } from './limiter'
export type { AuthOrg } from './org'
export type { AuthProvider } from './provider'
export type { AuthSession } from './session'
export type { AuthTransport } from './transport'
