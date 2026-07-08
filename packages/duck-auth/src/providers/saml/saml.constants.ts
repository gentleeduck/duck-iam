// 1 MiB cap on SAML response; larger XML inputs are adversarial.
export const SAML_RESPONSE_MAX = 1_048_576
// SAML 2.0 binding spec caps RelayState at 80 bytes; 256 is generous
// to accommodate apps that pack a serialized state object.
export const SAML_RELAY_STATE_MAX = 256
// DNS hostname max is 253 chars (RFC 1035).
export const SAML_HOST_MAX = 253

/** Default SAML knobs; overridden per-call via `saml(opts)` / `buildSpMetadata(opts)`. */
export const DEFAULT_SAML_CONFIG = {
  /** Provider id reported back to consumers. */
  providerId: 'saml',
  /** Want signed assertions? */
  wantAssertionsSigned: true,
  /** Want signed authn responses? */
  wantAuthnResponseSigned: true,
  /** NameID format the SP requires. */
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
}
