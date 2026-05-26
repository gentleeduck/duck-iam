/**
 * Public type-only barrel. All shapes are exposed via namespaces
 * (`Identity.IIdentity`, `Session.ISession`, ...) so consumers get
 * stable, semantically-grouped imports.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

export type { Channel } from './channel'
export type { TenantContext } from './context'
export type { Credential } from './credential'
export type { AuthError } from './error'
export type { Events } from './events'
export type { Hasher } from './hasher'
export type { Identity } from './identity'
export type { Limiter } from './limiter'
export type { Org } from './org'
export type { Provider } from './provider'
export type { Session } from './session'
export type { Transport } from './transport'
