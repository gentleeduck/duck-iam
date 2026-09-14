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

/** Max nameID length; it keys just-in-time provisioning and lands in an identity-store write. */
export const SAML_NAME_ID_MAX = 512

/** Limiter budget key prefix for both SAML phases. */
export const SAML_LIMITER_PREFIX = 'saml:'

/**
 * AuthnContextClassRefs that mean the IdP actually performed a second factor.
 *
 * Every SAML sign-in used to be stamped aal 2 whatever the IdP did, so a password-only IdP minted
 * a session that satisfied every step-up requirement in this library.
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

/**
 * The one detail string every refusal carries.
 *
 * Three distinct strings told an attacker which part of a forged assertion the verifier objected
 * to: a malformed body, a rejected signature and an unusable profile read differently. The real
 * reason still goes to `signin.failed`, which is the operator's to read.
 */
export const SAML_REFUSED = 'SAMLResponse rejected'
