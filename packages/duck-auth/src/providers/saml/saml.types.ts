/**
 * Every type the SAML provider exposes lives under this one namespace, so
 * consumers reach for `Saml.Client`, `Saml.Options`, etc. from a single place.
 */
export namespace Saml {
  /**
   * Subset of `@node-saml/node-saml` we depend on. Both v4 + v5 satisfy
   * this shape; consumers without the peerDep get AUTH/MISCONFIGURED
   * on first call.
   */
  export interface Client {
    getAuthorizeUrlAsync(relayState: string, host: string, opts: Record<string, unknown>): Promise<string>
    validatePostResponseAsync(body: { SAMLResponse: string }): Promise<{
      profile: Profile | null
      loggedOut: boolean
    }>
    /** Optional. node-saml exposes this synchronously. */
    generateServiceProviderMetadata?(decryptionCert?: string | null, signingCert?: string | null): string
    /** Optional. Builds an SP-initiated LogoutRequest URL (HTTP-Redirect binding). */
    getLogoutUrlAsync?(user: LogoutUser, relayState: string, opts: Record<string, unknown>): Promise<string>
    /** Optional. Validates an IdP-sent LogoutRequest or LogoutResponse (Redirect binding). */
    validateRedirectAsync?(
      query: Record<string, string>,
      originalQuery: string,
    ): Promise<{ profile: Profile | null; loggedOut: boolean }>
    /** Optional. Validates an IdP-sent LogoutRequest sent via HTTP-POST (rare). */
    validatePostRequestAsync?(body: { SAMLRequest: string }): Promise<{ profile: Profile | null; loggedOut: boolean }>
    /** Optional. Builds a LogoutResponse URL for an IdP-initiated logout. */
    getLogoutResponseUrl?(user: LogoutUser, relayState: string, opts: Record<string, unknown>, isError: boolean): string
  }

  /** Subset of node-saml's logout-user shape; sub = SAML nameID. */
  export interface LogoutUser {
    nameID: string
    nameIDFormat?: string
    sessionIndex?: string
  }

  /**
   * Subset of node-saml's profile we extract. Library projects 30+
   * attributes onto the oauth-style `{ sub, email?, name? }` shape the
   * rest of the auth lib expects.
   */
  export interface Profile {
    nameID: string
    nameIDFormat?: string
    email?: string
    attributes?: Record<string, string | string[]>
    /** What the IdP says it did to authenticate. Decides the session's aal; see `mfaAuthnContexts`. */
    authnContext?: string
    /** Assertion id, when the client surfaces one. Consumed once by `replayStore`. */
    ID?: string
    sessionIndex?: string
  }

  /** Cfg knobs for {@link saml}. */
  export interface Options<AppProfile = unknown> {
    /**
     * Provider id reported back to consumers (e.g. `'okta'`,
     * `'azure-saml'`). Default `'saml'`.
     */
    providerId?: string
    /**
     * Pre-built `Client` (the `@node-saml/node-saml` SAML class
     * instance). Required - SAML configuration is too varied to
     * express declaratively without depending on the library types.
     */
    client: Client
    /**
     * Callback URL the IdP POSTs the SAMLResponse to. Must exactly
     * match the AssertionConsumerService URL registered with the IdP.
     *
     * Checked against the client's own `callbackUrl` at construction: nothing here parses the
     * response, so the client is what validates `Destination` and `Recipient`, and the two
     * disagreeing meant this one was a presence test and nothing more.
     */
    callbackUrl: string
    /**
     * Translate the SAML profile into the app's `Profile` shape, and refuse the sign-in by throwing.
     * Called before `onSignIn`, which is what makes a projection written to sanitise IdP attributes
     * something other than dead code.
     */
    profileToIdentityProfile?: (profile: Profile) => AppProfile
    /**
     * Check the relay state the IdP echoed back against the one `begin` issued, and against the
     * tenant the response is being consumed under.
     *
     * This is the counterpart the CSRF guard never had. Without it an assertion an attacker obtained
     * for their own account, POSTed into a victim's browser, is indistinguishable from one the
     * victim asked for, and one provider instance serving several tenants accepts the same assertion
     * under any of them.
     */
    verifyRelayState?: (input: { relayState: string; tenantId?: string }) => Promise<boolean>
    /**
     * Accept a response carrying no relay state, which is the IdP-initiated flow. Default false.
     * Nothing binds an unsolicited assertion to a request or to a tenant, so it is opt-in.
     */
    allowUnsolicited?: boolean
    /**
     * Consume an assertion id exactly once. Returns false when it has been seen before.
     *
     * Replay protection otherwise lives in the client's InResponseTo cache, which this wrapper
     * neither configures nor requires, so one captured POST body minted a fresh session per repeat.
     */
    replayStore?: { consume: (assertionId: string) => Promise<boolean> }
    /**
     * NameID formats the SP accepts. Defaults to the one `DEFAULT_SAML_CONFIG` asks for. A transient
     * nameID changes on every login, so provisioning keyed on it creates a new account each time.
     */
    allowedNameIdFormats?: readonly string[]
    /** AuthnContextClassRefs that earn aal 2. Defaults to {@link SAML_MFA_AUTHN_CONTEXTS}. */
    mfaAuthnContexts?: readonly string[]
    /** Attribute names passed through to the hooks. Absent means every attribute the IdP sent. */
    allowedAttributes?: readonly string[]
    /** Limiter key for both phases. Defaults to one budget per tenant, which is coarse but bounded. */
    limiterKey?: (ctx: { tenantId?: string }, phase: 'begin' | 'complete') => string
    /**
     * onSignIn hook fires after a successful SAMLResponse. Use to
     * just-in-time provision identities (lookup by `nameID` or
     * `email`, create if missing, return identityId).
     */
    onSignIn: (input: { profile: Profile; tenantId?: string }) => Promise<{ identityId: string }>
  }

  /** Input to {@link saml}.begin. */
  export interface BeginInput {
    /** Caller-supplied relay state (CSRF guard); echoed back by IdP. */
    relayState: string
    /** Host the IdP redirects to (your app's origin). */
    host: string
  }

  /**
   * Input to {@link saml}.complete. Covers both flows:
   *   - SP-initiated: the SAMLResponse references an InResponseTo we issued.
   *   - IdP-initiated: the SAMLResponse is unsolicited. Whether this is
   *     accepted is a node-saml config knob (`allowUnsolicited: true`).
   */
  export interface CompleteInput {
    /** Raw SAMLResponse param from the IdP POST. */
    SAMLResponse: string
    /**
     * RelayState the IdP echoed back. Required unless `allowUnsolicited` is set: the value `begin`
     * issued as a CSRF guard had no counterpart on the way back.
     */
    relayState?: string
  }

  /** Input to {@link samlSloController}.beginSp. */
  export interface SloBeginSpInput {
    /** The SAML nameID of the user being logged out. */
    nameID: string
    nameIDFormat?: string
    sessionIndex?: string
    relayState: string
  }

  /** Input to {@link samlSloController}.completeSp. */
  export interface SloCompleteSpInput {
    /** IdP's response to our LogoutRequest (Redirect binding query params). */
    query: Record<string, string>
    /** The original query string captured at LogoutRequest send time, for sig verify. */
    originalQuery: string
  }

  /** Input to {@link samlSloController}.completeIdp. */
  export interface SloCompleteIdpInput {
    /** SAMLRequest param from the IdP-initiated logout (Redirect or POST). */
    query?: Record<string, string>
    originalQuery?: string
    SAMLRequest?: string
  }

  /** Result of {@link samlSloController}.completeIdp. */
  export interface SloCompleteIdpResult {
    /** SAML nameID of the user being logged out (the host should kill the matching session). */
    nameID: string | null
    /** A redirect URL to send the user to so the IdP gets a LogoutResponse. */
    redirectUrl: string
  }

  /** Cfg knobs for {@link buildSpMetadata}. */
  export interface MetadataOptions {
    /** SP entityID. Must match the AudienceRestriction set at the IdP. */
    entityId: string
    /** AssertionConsumerService URL (where SAMLResponse is POSTed). */
    acsUrl: string
    /** Single Logout Service URL. Optional; omit if you don't support SLO. */
    sloUrl?: string
    /**
     * X.509 certificate the SP uses to sign AuthnRequests and validate
     * encrypted assertions. PEM body without `-----BEGIN-----` markers.
     */
    signingCert?: string
    /** Cert used to decrypt encrypted assertions. PEM body, no markers. */
    decryptionCert?: string
    /** NameID format the SP requires. Default: emailAddress. */
    nameIdFormat?: string
    /** Display name for the IdP's UI. */
    displayName?: string
    /** Want signed assertions? Default true. */
    wantAssertionsSigned?: boolean
    /** Want signed authn responses? Default true. */
    wantAuthnResponseSigned?: boolean
  }
}
