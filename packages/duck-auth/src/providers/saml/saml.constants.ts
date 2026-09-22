/** 1 MiB on a SAML response; larger XML is adversarial. */
export const SAML_RESPONSE_MAX = 1_048_576
/** The SAML 2.0 binding spec caps RelayState at 80 bytes; 256 leaves room for an app that packs a
 *  serialised state object. */
export const SAML_RELAY_STATE_MAX = 256
/** RFC 1035 caps a DNS hostname at 253 chars. */
export const SAML_HOST_MAX = 253

/** Overridden per call through `saml(opts)` and `buildSpMetadata(opts)`. */
export const DEFAULT_SAML_CONFIG = {
  /** Provider id reported back to consumers. */
  providerId: 'saml',
  // What the SP *asks* for in its metadata document. What enforces it is the node-saml client, which
  // `SamlImpl`'s constructor refuses only when it is set to want neither.
  wantAssertionsSigned: true,
  wantAuthnResponseSigned: true,
  /** The SP asks the IdP for an email address as the NameID, which is what `profile.email` reads. */
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
}

/** Max nameID length; it keys just-in-time provisioning and lands in an identity-store write. */
export const SAML_NAME_ID_MAX = 512

/** Max assertion id length; it keys the replay store. An xsd:ID is an NCName, far under this. */
export const SAML_ASSERTION_ID_MAX = 256

/** Limiter budget key prefix for both SAML phases. */
export const SAML_LIMITER_PREFIX = 'saml:'

/**
 * AuthnContextClassRefs that mean the IdP actually performed a second factor.
 *
 * SECURITY: stamping every SAML sign-in aal 2 whatever the IdP did lets a password-only IdP mint a
 * session that satisfies every step-up requirement in this library.
 */
export const SAML_MFA_AUTHN_CONTEXTS = [
  'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:X509',
  'http://schemas.microsoft.com/claims/multipleauthn',
] as const

/** The one detail string every refusal carries. */
export const SAML_REFUSED = 'SAMLResponse rejected'
