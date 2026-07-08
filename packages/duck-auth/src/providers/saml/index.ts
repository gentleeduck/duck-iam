/**
 * SAML provider — self-contained capability folder.
 * The SP-initiated / IdP-initiated sign-in provider, SP metadata generation,
 * the Single Logout controller, and all types under the `Saml` namespace.
 */

export { DEFAULT_SAML_CONFIG, SAML_HOST_MAX, SAML_RELAY_STATE_MAX, SAML_RESPONSE_MAX } from './saml.constants'
export { buildSpMetadata } from './saml.metadata'
export { saml } from './saml.provider'
export { samlSloController } from './saml.slo'
export type { Saml } from './saml.types'
