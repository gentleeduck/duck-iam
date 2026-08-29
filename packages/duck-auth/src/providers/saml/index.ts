/**
 * SAML provider — self-contained capability folder.
 * The SP-initiated / IdP-initiated sign-in provider, SP metadata generation,
 * the Single Logout controller, and all types under the `Saml` namespace.
 */

export { buildSpMetadata } from './internal/metadata'
export { samlSloController } from './internal/slo'
export { SamlImpl, saml, samlImpl } from './saml'
export { DEFAULT_SAML_CONFIG, SAML_HOST_MAX, SAML_RELAY_STATE_MAX, SAML_RESPONSE_MAX } from './saml.constants'
export type { Saml } from './saml.types'
