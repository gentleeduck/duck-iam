/**
 * Public type-only barrel. All shapes are exposed via namespaces
 * (`Identity.IIdentity`, `Session.ISession`, ...) so consumers get
 * stable, semantically-grouped imports. Types are grouped into four
 * domain modules: identity, session, provider, infra.
 */

export type { Identity } from '~/core/identities/identities.types'
export type { Session } from '~/core/sessions/sessions.types'
export type { Credential, Org } from './identity'
export type { Channel, DataAtRest, Hasher, Idempotency, Kms, Limiter, TenantContext } from './infra'
export type { Anomaly, Events, Provider } from './provider'
export type { AuthError, Envelope, Transport } from './session'
