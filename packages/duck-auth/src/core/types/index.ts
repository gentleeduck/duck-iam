/**
 * Public type-only barrel. All shapes are exposed via namespaces
 * (`Identity.IIdentity`, `Session.ISession`, ...) so consumers get
 * stable, semantically-grouped imports. Types are grouped into four
 * domain modules: identity, session, provider, infra.
 */

export type { Anomaly } from '~/core/anomaly/anomaly.types'
export type { Idempotency } from '~/core/idempotency/idempotency.types'
export type { Identity } from '~/core/identities/identities.types'
export type { Org } from '~/core/orgs/orgs.types'
export type { Provider } from '~/core/provider/provider.types'
export type { Session } from '~/core/sessions/sessions.types'
export type { Credential } from './identity'
export type { Channel, DataAtRest, Hasher, Kms, Limiter, TenantContext } from './infra'
export type { Events } from './provider'
export type { AuthError, Envelope, Transport } from './session'
