/**
 * Public type-only barrel. All shapes are exposed via namespaces
 * (`Identity.IIdentity`, `Session.ISession`, ...) so consumers get
 * stable, semantically-grouped imports. Types are grouped into four
 * domain modules: identity, session, provider, infra.
 */

export type { AUTH_CREDENTIAL_KINDS, Credential } from './identity'
export type { DataAtRest, Kms, TenantContext } from './infra'
export type { Envelope, Transport } from './session'
